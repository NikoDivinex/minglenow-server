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
const COINS_DATA_FILE = path.join(__dirname, 'coins.json');
const ACCOUNTS_FILE = path.join(__dirname, 'accounts.json');
const UNBAN_PRICE_CENTS = 799; // $7.99

// ─── Accounts Persistence ───
let accountsData = { accounts: {}, usernameToId: {}, friends: {}, dms: {} };
// accounts: { "google_id": { username, email, gender, country, createdAt } }
// usernameToId: { "username_lower": "google_id" }
// friends: { "google_id": ["friend_google_id",...] }
// dms: { "convo_key": [{ from, text, timestamp },...] }

function loadAccounts() {
  try {
    if (fs.existsSync(ACCOUNTS_FILE)) {
      accountsData = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
      console.log(`[ACCOUNTS] Loaded ${Object.keys(accountsData.accounts).length} accounts`);
    }
  } catch (e) { console.error('[ACCOUNTS] Load error:', e.message); }
}

function saveAccounts() {
  try { fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accountsData, null, 2)); }
  catch (e) { console.error('[ACCOUNTS] Save error:', e.message); }
}

function getAccount(googleId) { return accountsData.accounts[googleId] || null; }

function getAccountByUsername(username) {
  const id = accountsData.usernameToId[username.toLowerCase()];
  return id ? { ...accountsData.accounts[id], googleId: id } : null;
}

function isUsernameTakenByAccount(username, excludeGoogleId) {
  const owner = accountsData.usernameToId[username.toLowerCase()];
  if (!owner) return false;
  return owner !== excludeGoogleId;
}

function createOrUpdateAccount(googleId, data) {
  const existing = accountsData.accounts[googleId];
  if (existing && data.username && data.username.toLowerCase() !== existing.username.toLowerCase()) {
    delete accountsData.usernameToId[existing.username.toLowerCase()];
  }
  accountsData.accounts[googleId] = {
    username: data.username || existing?.username || 'User',
    email: data.email || existing?.email || '',
    gender: data.gender || existing?.gender || '',
    country: data.country || existing?.country || '',
    bio: data.bio !== undefined ? data.bio : (existing?.bio || ''),
    lastUsernameChange: data.lastUsernameChange || existing?.lastUsernameChange || null,
    ownedFilters: existing?.ownedFilters || [],
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  accountsData.usernameToId[data.username.toLowerCase()] = googleId;
  saveAccounts();
}

function getDMKey(id1, id2) { return [id1, id2].sort().join(':'); }

function getDMs(id1, id2, limit = 50) {
  const key = getDMKey(id1, id2);
  if (!accountsData.dms) accountsData.dms = {};
  return (accountsData.dms[key] || []).slice(-limit);
}

function saveDM(fromId, toId, text) {
  const key = getDMKey(fromId, toId);
  if (!accountsData.dms) accountsData.dms = {};
  if (!accountsData.dms[key]) accountsData.dms[key] = [];
  accountsData.dms[key].push({ from: fromId, text, timestamp: Date.now() });
  if (accountsData.dms[key].length > 200) accountsData.dms[key] = accountsData.dms[key].slice(-200);
  saveAccounts();
}

function getFriends(googleId) {
  if (!accountsData.friends) accountsData.friends = {};
  return accountsData.friends[googleId] || [];
}

function addFriend(googleId, friendGoogleId) {
  if (!accountsData.friends) accountsData.friends = {};
  if (!accountsData.friends[googleId]) accountsData.friends[googleId] = [];
  if (!accountsData.friends[friendGoogleId]) accountsData.friends[friendGoogleId] = [];
  if (!accountsData.friends[googleId].includes(friendGoogleId)) {
    accountsData.friends[googleId].push(friendGoogleId);
  }
  if (!accountsData.friends[friendGoogleId].includes(googleId)) {
    accountsData.friends[friendGoogleId].push(googleId);
  }
  saveAccounts();
}

function removeFriendFromList(googleId, friendGoogleId) {
  if (!accountsData.friends) return;
  accountsData.friends[googleId] = (accountsData.friends[googleId] || []).filter(f => f !== friendGoogleId);
  accountsData.friends[friendGoogleId] = (accountsData.friends[friendGoogleId] || []).filter(f => f !== googleId);
  saveAccounts();
}

loadAccounts();

// ─── Gift Catalog ───
const GIFTS = {
  rose:    { name: 'Rose',    emoji: '🌹', cost: 5 },
  heart:   { name: 'Heart',   emoji: '❤️', cost: 10 },
  fire:    { name: 'Fire',    emoji: '🔥', cost: 15 },
  star:    { name: 'Star',    emoji: '⭐', cost: 25 },
  crown:   { name: 'Crown',   emoji: '👑', cost: 50 },
  diamond: { name: 'Diamond', emoji: '💎', cost: 100 },
  rocket:  { name: 'Rocket',  emoji: '🚀', cost: 200 },
  galaxy:  { name: 'Galaxy',  emoji: '🌌', cost: 500 },
};

// ─── Coin Packages ───
const COIN_PACKAGES = {
  pack1: { coins: 100,  price: '0.99',  label: '100 M Coins' },
  pack2: { coins: 600,  price: '4.99',  label: '600 M Coins' },
  pack3: { coins: 1500, price: '9.99',  label: '1,500 M Coins' },
  pack4: { coins: 5000, price: '24.99', label: '5,000 M Coins' },
};

// ─── Coins Persistence ───
let coinsData = { balances: {}, transactions: [], totalRevenue: 0, totalGifts: 0, perks: {}, recentPartners: {}, giftsReceived: {}, usernames: {} };
// balances: { "ip": coinCount }
// perks: { "ip": { nameColor: "gold", bubbleTheme: "neon", entrance: "fire", region: "us" } }
// recentPartners: { "ip": ["partnerId1","partnerId2"...] }
// giftsReceived: { "ip": totalCoinsReceived }
// usernames: { "ip": "lastKnownUsername" }

// ─── Perks Shop ───
const PERKS = {
  nameColors: {
    gold:    { name: 'Gold',    color: '#f1c40f', cost: 50 },
    purple:  { name: 'Purple',  color: '#a55eea', cost: 50 },
    red:     { name: 'Red',     color: '#e84393', cost: 50 },
    cyan:    { name: 'Cyan',    color: '#00cec9', cost: 50 },
    green:   { name: 'Green',   color: '#00b894', cost: 50 },
    rainbow: { name: 'Rainbow', color: 'rainbow',  cost: 150 },
  },
  bubbleThemes: {
    neon:     { name: 'Neon Glow',   cost: 75 },
    gradient: { name: 'Gradient',    cost: 75 },
    dark:     { name: 'Dark Mode',   cost: 75 },
    retro:    { name: 'Retro',       cost: 100 },
    royal:    { name: 'Royal Gold',  cost: 150 },
  },
  entrances: {
    fire:    { name: 'Fire Entrance',    emoji: '🔥', cost: 100 },
    star:    { name: 'Star Entrance',    emoji: '⭐', cost: 100 },
    crown:   { name: 'VIP Entrance',     emoji: '👑', cost: 200 },
    diamond: { name: 'Diamond Entrance', emoji: '💎', cost: 300 },
    rocket:  { name: 'Rocket Entrance',  emoji: '🚀', cost: 500 },
  },
  regions: {
    any: { name: 'Any Region', cost: 0 },
    us:  { name: 'North America', cost: 25 },
    eu:  { name: 'Europe', cost: 25 },
    asia:{ name: 'Asia', cost: 25 },
    latam:{ name: 'Latin America', cost: 25 },
    mena:{ name: 'Middle East', cost: 25 },
  },
  reconnectCost: 50,
};

function loadCoins() {
  try {
    if (fs.existsSync(COINS_DATA_FILE)) {
      coinsData = JSON.parse(fs.readFileSync(COINS_DATA_FILE, 'utf8'));
      console.log(`[COINS] Loaded ${Object.keys(coinsData.balances).length} balances`);
    }
  } catch (e) { console.error('[COINS] Load error:', e.message); }
}

function saveCoins() {
  try { fs.writeFileSync(COINS_DATA_FILE, JSON.stringify(coinsData, null, 2)); }
  catch (e) { console.error('[COINS] Save error:', e.message); }
}

function getBalance(key) { return coinsData.balances[key] || 0; }

// Get the coin/perk storage key for a client - googleId if signed in, ip if guest
function getCoinKey(clientData) {
  return clientData.googleId ? `g:${clientData.googleId}` : clientData.ip;
}

// Get coin key from HTTP request (checks googleId query param or falls back to IP)
function getKeyFromReq(req) {
  try {
    const url = new URL(req.url, 'http://localhost');
    const gid = url.searchParams.get('googleId');
    if (gid) return `g:${gid}`;
  } catch (e) {}
  return getClientIP(req);
}

function addCoins(ip, amount, reason) {
  coinsData.balances[ip] = (coinsData.balances[ip] || 0) + amount;
  coinsData.transactions.push({ ip: ip.slice(0, 8) + '***', amount, reason, timestamp: new Date().toISOString() });
  if (coinsData.transactions.length > 500) coinsData.transactions = coinsData.transactions.slice(-500);
  saveCoins();
}

function spendCoins(ip, amount) {
  if ((coinsData.balances[ip] || 0) < amount) return false;
  coinsData.balances[ip] -= amount;
  saveCoins();
  return true;
}

loadCoins();

function getUserPerks(ip) {
  return coinsData.perks?.[ip] || {};
}

function setUserPerk(ip, perkType, perkId) {
  if (!coinsData.perks) coinsData.perks = {};
  if (!coinsData.perks[ip]) coinsData.perks[ip] = {};
  coinsData.perks[ip][perkType] = perkId;
  saveCoins();
}

function getRecentPartners(ip) {
  return coinsData.recentPartners?.[ip] || [];
}

function addRecentPartner(ip, partnerId, partnerIp) {
  if (!coinsData.recentPartners) coinsData.recentPartners = {};
  if (!coinsData.recentPartners[ip]) coinsData.recentPartners[ip] = [];
  // Store last 10 partners
  const list = coinsData.recentPartners[ip];
  const entry = { id: partnerId, ip: partnerIp, timestamp: Date.now() };
  list.unshift(entry);
  if (list.length > 10) list.length = 10;
  saveCoins();
}

function trackGiftReceived(ip, amount) {
  if (!coinsData.giftsReceived) coinsData.giftsReceived = {};
  coinsData.giftsReceived[ip] = (coinsData.giftsReceived[ip] || 0) + amount;
  saveCoins();
}

function setUsername(ip, username) {
  if (!coinsData.usernames) coinsData.usernames = {};
  if (!coinsData.usernameToIP) coinsData.usernameToIP = {};
  if (username) {
    // Remove old username claim for this IP
    const oldName = coinsData.usernames[ip];
    if (oldName && coinsData.usernameToIP[oldName.toLowerCase()] === ip) {
      delete coinsData.usernameToIP[oldName.toLowerCase()];
    }
    coinsData.usernames[ip] = username;
    coinsData.usernameToIP[username.toLowerCase()] = ip;
    saveCoins();
  }
}

function isUsernameTaken(username, requestingIP) {
  if (!coinsData.usernameToIP) coinsData.usernameToIP = {};
  const owner = coinsData.usernameToIP[username.toLowerCase()];
  if (!owner) return false; // not taken
  return owner !== requestingIP; // taken by someone else
}

function getUsernameForIP(ip) {
  if (!coinsData.usernames) return null;
  return coinsData.usernames[ip] || null;
}

function getLeaderboard(limit = 10) {
  if (!coinsData.giftsReceived) return [];
  const entries = Object.entries(coinsData.giftsReceived)
    .map(([ip, total]) => ({
      username: (coinsData.usernames || {})[ip] || 'Anonymous',
      coinsReceived: total,
      nameColor: (coinsData.perks || {})[ip]?.nameColor || null,
    }))
    .sort((a, b) => b.coinsReceived - a.coinsReceived)
    .slice(0, limit);
  return entries;
}

// ─── Admin Config ───
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'MingleNow2026!';
const adminTokens = new Set();

function generateAdminToken() {
  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.add(token);
  // Expire token after 24 hours
  setTimeout(() => adminTokens.delete(token), 24 * 60 * 60 * 1000);
  return token;
}

function isValidAdmin(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return false;
  return adminTokens.has(auth.split('Bearer ')[1]);
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

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
function banIP(ip, reason, username, googleId) {
  const unbanToken = crypto.randomBytes(16).toString('hex');
  banData.bannedIPs[ip] = { reason, timestamp: new Date().toISOString(), unbanToken, paid: false, username: username || '', googleId: googleId || '' };
  banData.banLog.push({ ip: ip.slice(0, 8) + '***', reason, timestamp: new Date().toISOString(), username: username || '', googleId: googleId || '' });
  // Also ban the Google account if present
  if (googleId) banGoogleAccount(googleId, reason, username);
  saveBans();
  console.log(`[BAN] ${username || ip.slice(0, 8) + '***'}: ${reason}${googleId ? ' (Google: ' + googleId.slice(0, 8) + '...)' : ''}`);
  return unbanToken;
}

function banGoogleAccount(googleId, reason, username) {
  if (!banData.bannedGoogleIds) banData.bannedGoogleIds = {};
  banData.bannedGoogleIds[googleId] = { reason, timestamp: new Date().toISOString(), username: username || '', paid: false };
  saveBans();
}

function isIPBanned(ip) {
  const ban = banData.bannedIPs[ip];
  return ban && !ban.paid;
}

function isGoogleBanned(googleId) {
  if (!googleId || !banData.bannedGoogleIds) return false;
  const ban = banData.bannedGoogleIds[googleId];
  return ban && !ban.paid;
}

function isUserBanned(ip, googleId) {
  return isIPBanned(ip) || isGoogleBanned(googleId);
}

function unbanGoogleAccount(googleId) {
  if (banData.bannedGoogleIds && banData.bannedGoogleIds[googleId]) {
    banData.bannedGoogleIds[googleId].paid = true;
    banData.bannedGoogleIds[googleId].unbannedAt = new Date().toISOString();
    saveBans();
    return true;
  }
  return false;
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
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

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
  if (req.url?.startsWith('/check-ban')) {
    const ip = getClientIP(req);
    const params = new URL(req.url, 'http://localhost').searchParams;
    const googleId = params.get('googleId') || '';
    const ipBanned = isIPBanned(ip);
    const googleBanned = isGoogleBanned(googleId);
    const banned = ipBanned || googleBanned;
    const info = getBanInfo(ip);
    const googleInfo = banData.bannedGoogleIds?.[googleId];
    const reason = ipBanned ? info?.reason : googleInfo?.reason || null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ banned, reason: banned ? reason : null, ipBanned, googleBanned }));
    return;
  }

  // Create PayPal order for unban
  if (req.url === '/create-unban-order' && req.method === 'POST') {
    try {
      const ip = getClientIP(req);
      const data = await readBody(req);
      const googleId = data.googleId || '';
      const ipBanned = isIPBanned(ip);
      const googleBanned = isGoogleBanned(googleId);

      if (!ipBanned && !googleBanned) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not banned' }));
        return;
      }

      const banInfo = getBanInfo(ip);
      const unbanToken = banInfo?.unbanToken || '';

      const clientId = process.env.PAYPAL_CLIENT_ID;
      const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
      const paypalBase = process.env.PAYPAL_MODE === 'live'
        ? 'https://api-m.paypal.com'
        : 'https://api-m.sandbox.paypal.com';

      if (!clientId || !clientSecret) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'PayPal not configured', message: 'Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET on Railway' }));
        return;
      }

      const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'grant_type=client_credentials',
      });
      const authData = await authRes.json();

      const orderRes = await fetch(`${paypalBase}/v2/checkout/orders`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authData.access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          intent: 'CAPTURE',
          purchase_units: [{
            amount: { currency_code: 'USD', value: '7.99' },
            description: 'MingleNow Account Unban',
            custom_id: `${ip}|${unbanToken}|${googleId}`,
          }],
        }),
      });
      const orderData = await orderRes.json();

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ orderId: orderData.id }));
    } catch (e) {
      console.error('[PAYPAL ERROR]', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // Capture PayPal order after user approves
  if (req.url === '/capture-unban-order' && req.method === 'POST') {
    try {
      const data = await readBody(req);
      const ip = getClientIP(req);
      const clientId = process.env.PAYPAL_CLIENT_ID;
      const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
      const paypalBase = process.env.PAYPAL_MODE === 'live'
        ? 'https://api-m.paypal.com'
        : 'https://api-m.sandbox.paypal.com';

      if (!data.orderId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'orderId required' }));
        return;
      }

      const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'grant_type=client_credentials',
      });
      const authData = await authRes.json();

      const captureRes = await fetch(`${paypalBase}/v2/checkout/orders/${data.orderId}/capture`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authData.access_token}`,
          'Content-Type': 'application/json',
        },
      });
      const captureData = await captureRes.json();

      if (captureData.status === 'COMPLETED') {
        const customId = captureData.purchase_units?.[0]?.payments?.captures?.[0]?.custom_id
          || captureData.purchase_units?.[0]?.custom_id || '';
        const parts = customId.split('|');
        const bannedIP = parts[0] || ip;
        const unbanToken = parts[1] || '';
        const googleId = parts[2] || '';

        // Unban IP
        const banInfo = getBanInfo(bannedIP);
        if (banInfo && (!unbanToken || banInfo.unbanToken === unbanToken)) {
          unbanIP(bannedIP);
        } else {
          unbanIP(ip);
        }

        // Also unban Google account if present
        if (googleId) {
          unbanGoogleAccount(googleId);
          console.log(`[PAYPAL] Unban payment completed for Google account ${googleId.slice(0, 8)}...`);
        }

        console.log(`[PAYPAL] Unban payment completed for IP ${bannedIP.slice(0, 8)}***`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, status: 'COMPLETED' }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, status: captureData.status }));
      }
    } catch (e) {
      console.error('[PAYPAL CAPTURE ERROR]', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // ═══════════════════════════════════════════
  // ACCOUNTS & AUTH
  // ═══════════════════════════════════════════

  // Google sign-in: verify token and create/update account
  if (req.url === '/auth/google' && req.method === 'POST') {
    try {
      const data = await readBody(req);
      // data: { googleId, email, name, username, gender, country }
      if (!data.googleId || !data.email) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Google ID and email required' }));
        return;
      }

      const username = (data.username || data.name || 'User').slice(0, 20).replace(/[^a-zA-Z0-9_]/g, '');
      if (username.length < 2) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Username must be 2-20 characters' }));
        return;
      }

      // Check if username taken by someone else
      if (isUsernameTakenByAccount(username, data.googleId)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Username is already taken' }));
        return;
      }

      createOrUpdateAccount(data.googleId, {
        username,
        email: data.email,
        gender: data.gender || '',
        country: data.country || '',
      });

      const account = getAccount(data.googleId);
      console.log(`[AUTH] ${username} signed in (${data.email})`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, account, googleId: data.googleId }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // Get account profile
  if (req.url?.startsWith('/auth/profile?')) {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const gid = params.get('googleId');
    if (gid) {
      const acc = getAccount(gid);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ account: acc }));
    } else {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'googleId required' }));
    }
    return;
  }

  // Check username availability for accounts
  if (req.url?.startsWith('/auth/check-username?')) {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const name = params.get('name');
    const gid = params.get('googleId') || '';
    const taken = isUsernameTakenByAccount(name, gid);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ available: !taken }));
    return;
  }

  // Update profile (bio, gender, country — free)
  if (req.url === '/auth/update-profile' && req.method === 'POST') {
    const data = await readBody(req);
    if (!data.googleId) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'googleId required' })); return; }
    const acc = getAccount(data.googleId);
    if (!acc) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Account not found' })); return; }

    // Update bio, gender, country (keep existing username)
    createOrUpdateAccount(data.googleId, {
      username: acc.username,
      email: acc.email,
      bio: typeof data.bio === 'string' ? data.bio.slice(0, 200) : acc.bio,
      gender: data.gender || acc.gender,
      country: data.country || acc.country,
      lastUsernameChange: acc.lastUsernameChange,
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Create PayPal order for username change ($2.99)
  if (req.url === '/auth/change-username-order' && req.method === 'POST') {
    try {
      const data = await readBody(req);
      if (!data.googleId || !data.newUsername) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'googleId and newUsername required' }));
        return;
      }

      const acc = getAccount(data.googleId);
      if (!acc) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Account not found' })); return; }

      // Check 30-day cooldown
      if (acc.lastUsernameChange) {
        const daysSince = (Date.now() - new Date(acc.lastUsernameChange).getTime()) / (1000 * 60 * 60 * 24);
        if (daysSince < 30) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Wait ${Math.ceil(30 - daysSince)} more days before changing again` }));
          return;
        }
      }

      const newName = data.newUsername.slice(0, 20).replace(/[^a-zA-Z0-9_]/g, '');
      if (newName.length < 2) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Username too short' })); return; }

      if (isUsernameTakenByAccount(newName, data.googleId)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Username is already taken' }));
        return;
      }

      const clientId = process.env.PAYPAL_CLIENT_ID;
      const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
      const paypalBase = process.env.PAYPAL_MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';

      if (!clientId || !clientSecret) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'PayPal not configured' }));
        return;
      }

      const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
        method: 'POST',
        headers: { 'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials',
      });
      const authData = await authRes.json();

      const orderRes = await fetch(`${paypalBase}/v2/checkout/orders`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authData.access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          intent: 'CAPTURE',
          purchase_units: [{ amount: { currency_code: 'USD', value: '2.99' }, description: 'MingleNow Username Change', custom_id: `uname|${data.googleId}|${newName}` }],
        }),
      });
      const orderData = await orderRes.json();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ orderId: orderData.id }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // Capture username change payment
  if (req.url === '/auth/capture-username-change' && req.method === 'POST') {
    try {
      const data = await readBody(req);
      const clientId = process.env.PAYPAL_CLIENT_ID;
      const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
      const paypalBase = process.env.PAYPAL_MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';

      const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
        method: 'POST',
        headers: { 'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials',
      });
      const authData = await authRes.json();

      const captureRes = await fetch(`${paypalBase}/v2/checkout/orders/${data.orderId}/capture`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authData.access_token}`, 'Content-Type': 'application/json' },
      });
      const captureData = await captureRes.json();

      if (captureData.status === 'COMPLETED') {
        const customId = captureData.purchase_units?.[0]?.payments?.captures?.[0]?.custom_id || '';
        const [, googleId, newName] = customId.split('|');
        const gid = googleId || data.googleId;
        const username = newName || data.newUsername;

        if (gid && username) {
          // Final check: username still available
          if (isUsernameTakenByAccount(username, gid)) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Username was taken while processing payment. Contact support for a refund.' }));
            return;
          }

          const acc = getAccount(gid);
          createOrUpdateAccount(gid, {
            username,
            email: acc?.email || '',
            bio: acc?.bio || '',
            gender: acc?.gender || '',
            country: acc?.country || '',
            lastUsernameChange: new Date().toISOString(),
          });

          coinsData.totalRevenue = (coinsData.totalRevenue || 0) + 2.99;
          saveCoins();
          console.log(`[USERNAME] ${gid.slice(0, 8)}... changed to "${username}" ($2.99)`);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, username }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Missing data' }));
        }
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Payment not completed' }));
      }
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // ═══════════════════════════════════════════
  // FRIENDS API
  // ═══════════════════════════════════════════

  // Add friend by username
  if (req.url === '/friends/add' && req.method === 'POST') {
    const data = await readBody(req);
    if (!data.googleId || !data.friendUsername) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'googleId and friendUsername required' }));
      return;
    }
    const friendAcc = getAccountByUsername(data.friendUsername);
    if (!friendAcc) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'User not found or not signed in' }));
      return;
    }
    if (friendAcc.googleId === data.googleId) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: "Can't add yourself" }));
      return;
    }
    const existing = getFriends(data.googleId);
    if (existing.includes(friendAcc.googleId)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Already friends' }));
      return;
    }
    addFriend(data.googleId, friendAcc.googleId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Remove friend
  if (req.url === '/friends/remove' && req.method === 'POST') {
    const data = await readBody(req);
    if (!data.googleId || !data.friendUsername) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'googleId and friendUsername required' }));
      return;
    }
    const friendAcc = getAccountByUsername(data.friendUsername);
    if (friendAcc) removeFriendFromList(data.googleId, friendAcc.googleId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Get friends list
  if (req.url?.startsWith('/friends/list?')) {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const gid = params.get('googleId');
    if (!gid) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'googleId required' })); return; }
    const friendIds = getFriends(gid);
    const friends = friendIds.map(fid => {
      const acc = getAccount(fid);
      if (!acc) return null;
      // Check if online
      let online = false;
      clients.forEach((d) => { if (d.googleId === fid) online = true; });
      return { username: acc.username, gender: acc.gender, country: acc.country, online, googleId: fid };
    }).filter(Boolean);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ friends }));
    return;
  }

  // Get DM history
  if (req.url?.startsWith('/friends/messages?')) {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const gid = params.get('googleId');
    const friendUsername = params.get('friend');
    if (!gid || !friendUsername) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'params required' })); return; }
    const friendAcc = getAccountByUsername(friendUsername);
    if (!friendAcc) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ messages: [] })); return; }
    const msgs = getDMs(gid, friendAcc.googleId);
    const mapped = msgs.map(m => ({ text: m.text, fromMe: m.from === gid, timestamp: m.timestamp }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ messages: mapped }));
    return;
  }

  // ═══════════════════════════════════════════
  // USERNAME SYSTEM
  // ═══════════════════════════════════════════

  // Check if a username is available
  if (req.url?.startsWith('/username/check?')) {
    const params = new URL(req.url, `http://localhost`).searchParams;
    const name = params.get('name');
    const ip = getClientIP(req);
    if (!name) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'name required' }));
      return;
    }
    const taken = isUsernameTaken(name, ip);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ available: !taken, username: name }));
    return;
  }

  // Claim / register a username
  if (req.url === '/username/claim' && req.method === 'POST') {
    const ip = getClientIP(req);
    const data = await readBody(req);
    const name = (data.username || '').trim().slice(0, 20).replace(/[^a-zA-Z0-9_]/g, '');

    if (name.length < 2) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Username must be 2-20 characters' }));
      return;
    }

    if (isUsernameTaken(name, ip)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Username is already taken' }));
      return;
    }

    setUsername(ip, name);
    console.log(`[USERNAME] ${ip.slice(0, 8)}*** claimed "${name}"`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, username: name }));
    return;
  }

  // Get my saved username
  if (req.url === '/username/mine') {
    const ip = getClientIP(req);
    const name = getUsernameForIP(ip);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ username: name }));
    return;
  }

  // ═══════════════════════════════════════════
  // PUBLIC LEADERBOARD (no auth needed)
  // ═══════════════════════════════════════════
  if (req.url === '/leaderboard') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ leaderboard: getLeaderboard(15) }));
    return;
  }

  // ═══════════════════════════════════════════
  // M COINS API
  // ═══════════════════════════════════════════

  // ═══ FILTERS ═══

  // Get user's owned filters
  if (req.url?.startsWith('/filters/mine')) {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const gid = params.get('googleId');
    if (!gid) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ filters: [] })); return; }
    const acc = getAccount(gid);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ filters: acc?.ownedFilters || [] }));
    return;
  }

  // Buy a filter with M Coins
  if (req.url === '/filters/buy' && req.method === 'POST') {
    const data = await readBody(req);
    if (!data.googleId || !data.filterId || !data.cost) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing fields' }));
      return;
    }

    const coinKey = `g:${data.googleId}`;
    const acc = getAccount(data.googleId);
    if (!acc) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'Account not found' })); return; }

    // Check if already owned
    if (acc.ownedFilters && acc.ownedFilters.includes(data.filterId)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, balance: getBalance(coinKey) }));
      return;
    }

    // Spend coins
    if (!spendCoins(coinKey, data.cost)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not enough coins', balance: getBalance(coinKey) }));
      return;
    }

    // Add filter to account
    if (!acc.ownedFilters) acc.ownedFilters = [];
    acc.ownedFilters.push(data.filterId);
    accountsData.accounts[data.googleId] = acc;
    saveAccounts();

    // Notify user's websocket
    clients.forEach((d, ws) => {
      if (d.googleId === data.googleId) send(ws, { type: 'coins_updated', balance: getBalance(coinKey) });
    });

    console.log(`[FILTER] ${acc.username} bought filter "${data.filterId}" for ${data.cost} coins`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, balance: getBalance(coinKey) }));
    return;
  }

  // Get coin balance
  if (req.url?.startsWith('/coins/balance')) {
    const key = getKeyFromReq(req);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ balance: getBalance(key) }));
    return;
  }

  // Get gift catalog and packages
  if (req.url === '/coins/catalog') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ gifts: GIFTS, packages: COIN_PACKAGES }));
    return;
  }

  // Create PayPal order for coin purchase
  if (req.url === '/coins/create-order' && req.method === 'POST') {
    try {
      const data = await readBody(req);

      // Require Google sign-in to purchase coins
      if (!data.googleId) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Sign in with Google to purchase M Coins' }));
        return;
      }

      const coinKey = `g:${data.googleId}`;
      const pack = COIN_PACKAGES[data.packageId];

      if (!pack) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid package' }));
        return;
      }

      const clientId = process.env.PAYPAL_CLIENT_ID;
      const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
      const paypalBase = process.env.PAYPAL_MODE === 'live'
        ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';

      if (!clientId || !clientSecret) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'PayPal not configured' }));
        return;
      }

      const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'grant_type=client_credentials',
      });
      const authData = await authRes.json();

      const orderRes = await fetch(`${paypalBase}/v2/checkout/orders`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authData.access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          intent: 'CAPTURE',
          purchase_units: [{
            amount: { currency_code: 'USD', value: pack.price },
            description: `MingleNow ${pack.label}`,
            custom_id: `coins|${coinKey}|${data.packageId}`,
          }],
        }),
      });
      const orderData = await orderRes.json();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ orderId: orderData.id }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // Capture PayPal coin purchase
  if (req.url === '/coins/capture-order' && req.method === 'POST') {
    try {
      const data = await readBody(req);
      const clientId = process.env.PAYPAL_CLIENT_ID;
      const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
      const paypalBase = process.env.PAYPAL_MODE === 'live'
        ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';

      const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'grant_type=client_credentials',
      });
      const authData = await authRes.json();

      const captureRes = await fetch(`${paypalBase}/v2/checkout/orders/${data.orderId}/capture`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authData.access_token}`, 'Content-Type': 'application/json' },
      });
      const captureData = await captureRes.json();

      if (captureData.status === 'COMPLETED') {
        const customId = captureData.purchase_units?.[0]?.payments?.captures?.[0]?.custom_id || '';
        const [, coinKey, packageId] = customId.split('|');
        const pack = COIN_PACKAGES[packageId];

        if (pack && coinKey) {
          addCoins(coinKey, pack.coins, `Purchased ${pack.label} ($${pack.price})`);
          coinsData.totalRevenue = (coinsData.totalRevenue || 0) + parseFloat(pack.price);
          saveCoins();
          console.log(`[COINS] ${coinKey.slice(0, 12)}*** bought ${pack.label}`);

          // Notify the user's websocket if they're connected
          clients.forEach((d, ws) => {
            if (getCoinKey(d) === coinKey) send(ws, { type: 'coins_updated', balance: getBalance(coinKey) });
          });
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, balance: getBalance(coinKey) }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // Get perks shop catalog
  if (req.url === '/perks/catalog') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ perks: PERKS }));
    return;
  }

  // Get user's active perks
  if (req.url?.startsWith('/perks/mine')) {
    const key = getKeyFromReq(req);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ perks: getUserPerks(key), balance: getBalance(key) }));
    return;
  }

  // Buy a perk
  if (req.url === '/perks/buy' && req.method === 'POST') {
    const data = await readBody(req);
    const key = data.googleId ? `g:${data.googleId}` : getClientIP(req);
    const { type, id } = data;

    let cost = 0;
    let valid = false;
    if (id === 'none') {
      valid = true; cost = 0;
    } else if (type === 'nameColor' && PERKS.nameColors[id]) { cost = PERKS.nameColors[id].cost; valid = true; }
    else if (type === 'bubbleTheme' && PERKS.bubbleThemes[id]) { cost = PERKS.bubbleThemes[id].cost; valid = true; }
    else if (type === 'entrance' && PERKS.entrances[id]) { cost = PERKS.entrances[id].cost; valid = true; }
    else if (type === 'region' && PERKS.regions[id]) { cost = PERKS.regions[id].cost; valid = true; }

    if (!valid) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid perk' }));
      return;
    }

    const current = getUserPerks(key);
    if (current[type] === id) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Already equipped', balance: getBalance(key), perks: getUserPerks(key) }));
      return;
    }

    if (cost > 0 && !spendCoins(key, cost)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not enough coins', balance: getBalance(key) }));
      return;
    }

    setUserPerk(key, type, id);

    clients.forEach((d, ws) => {
      if (getCoinKey(d) === key) {
        send(ws, { type: 'perks_updated', perks: getUserPerks(key), balance: getBalance(key) });
      }
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, balance: getBalance(key), perks: getUserPerks(key) }));
    return;
  }

  // ═══════════════════════════════════════════
  // ADMIN API
  // ═══════════════════════════════════════════

  // Admin login
  if (req.url === '/admin/login' && req.method === 'POST') {
    const data = await readBody(req);
    if (data.username === ADMIN_USER && data.password === ADMIN_PASS) {
      const token = generateAdminToken();
      console.log(`[ADMIN] Login successful`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, token }));
    } else {
      console.log(`[ADMIN] Failed login attempt`);
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Invalid credentials' }));
    }
    return;
  }

  // Admin verify token
  if (req.url === '/admin/verify') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ valid: isValidAdmin(req) }));
    return;
  }

  // ── All routes below require admin auth ──
  if (req.url?.startsWith('/admin/') && req.url !== '/admin/login' && req.url !== '/admin/verify') {
    if (!isValidAdmin(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
  }

  // Admin dashboard stats
  if (req.url === '/admin/stats') {
    const activeBans = Object.entries(banData.bannedIPs).filter(([_, v]) => !v.paid);
    const paidUnbans = Object.entries(banData.bannedIPs).filter(([_, v]) => v.paid);
    const onlineUsers = [];
    clients.forEach((data, ws) => {
      if (data.isBot) return; // Skip bots
      const ck = getCoinKey(data);
      onlineUsers.push({
        id: data.id,
        ip: data.ip.slice(0, 8) + '***',
        fullIP: data.ip,
        username: data.username || '',
        signedIn: !!data.googleId,
        googleId: data.googleId || null,
        coinKey: ck,
        interests: data.interests,
        hasPartner: !!data.partner,
        warnings: data.warnings,
        coins: getBalance(ck),
      });
    });

    // Also list all registered accounts
    const registeredAccounts = Object.entries(accountsData.accounts).map(([gid, acc]) => ({
      googleId: gid,
      username: acc.username,
      email: acc.email,
      gender: acc.gender,
      country: acc.country,
      coins: getBalance(`g:${gid}`),
      createdAt: acc.createdAt,
    }));

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      online: clients.size,
      waiting: waitingQueue.length,
      connected: connectedPairs.size,
      totalBans: activeBans.length,
      totalUnbans: paidUnbans.length,
      revenue: paidUnbans.length * 7.99 + (coinsData.totalRevenue || 0),
      coinRevenue: coinsData.totalRevenue || 0,
      totalGifts: coinsData.totalGifts || 0,
      totalAccounts: Object.keys(accountsData.accounts).length,
      activeBots: activeBots.size,
      recentBans: banData.banLog.slice(-50).reverse(),
      onlineUsers,
      registeredAccounts,
    }));
    return;
  }

  // Admin get all bans
  if (req.url === '/admin/bans') {
    const ipBans = Object.entries(banData.bannedIPs).map(([ip, info]) => ({
      type: 'ip',
      ip: ip.slice(0, 8) + '***',
      fullIP: ip,
      reason: info.reason,
      timestamp: info.timestamp,
      paid: info.paid,
      unbannedAt: info.unbannedAt || null,
      username: info.username || '',
      googleId: info.googleId || '',
    }));
    const googleBans = Object.entries(banData.bannedGoogleIds || {}).map(([gid, info]) => ({
      type: 'google',
      googleId: gid,
      reason: info.reason,
      timestamp: info.timestamp,
      paid: info.paid,
      unbannedAt: info.unbannedAt || null,
      username: info.username || '',
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ bans: ipBans, googleBans }));
    return;
  }

  // Admin manually ban — supports IP, googleId, or username
  if (req.url === '/admin/ban' && req.method === 'POST') {
    const data = await readBody(req);
    const reason = data.reason || 'Banned by admin';
    let banned = false;

    // Ban by googleId (Google account ban)
    if (data.googleId) {
      banGoogleAccount(data.googleId, reason, data.username || '');
      // Also ban their IP if they're online
      clients.forEach((d, ws) => {
        if (d.googleId === data.googleId) {
          banIP(d.ip, reason, d.username, d.googleId);
          send(ws, { type: 'banned', reason });
          unpairUser(ws); removeFromQueue(ws);
          setTimeout(() => ws.close(), 500);
        }
      });
      banned = true;
    }
    // Ban by username (look up account)
    else if (data.username) {
      const acc = getAccountByUsername(data.username);
      if (acc) {
        banGoogleAccount(acc.googleId, reason, data.username);
        clients.forEach((d, ws) => {
          if (d.googleId === acc.googleId || d.username === data.username) {
            banIP(d.ip, reason, d.username, d.googleId);
            send(ws, { type: 'banned', reason });
            unpairUser(ws); removeFromQueue(ws);
            setTimeout(() => ws.close(), 500);
          }
        });
        banned = true;
      }
    }
    // Ban by IP (for strangers / non-signed-in users)
    if (data.ip) {
      banIP(data.ip, reason);
      clients.forEach((d, ws) => {
        if (d.ip === data.ip) {
          send(ws, { type: 'banned', reason });
          unpairUser(ws); removeFromQueue(ws);
          setTimeout(() => ws.close(), 500);
        }
      });
      banned = true;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: banned }));
    return;
  }

  // Admin manually unban — supports IP and googleId
  if (req.url === '/admin/unban' && req.method === 'POST') {
    const data = await readBody(req);
    if (data.ip) unbanIP(data.ip);
    if (data.googleId) unbanGoogleAccount(data.googleId);
    // Also unban by username lookup
    if (data.username) {
      const acc = getAccountByUsername(data.username);
      if (acc) unbanGoogleAccount(acc.googleId);
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Admin kick a user by ID
  if (req.url === '/admin/kick' && req.method === 'POST') {
    const data = await readBody(req);
    let kicked = false;
    clients.forEach((d, ws) => {
      if (d.id === data.userId) {
        send(ws, { type: 'partner_disconnected' });
        unpairUser(ws);
        removeFromQueue(ws);
        ws.close();
        kicked = true;
      }
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: kicked }));
    return;
  }

  // Admin broadcast message to all users
  if (req.url === '/admin/broadcast' && req.method === 'POST') {
    const data = await readBody(req);
    if (data.message) {
      let count = 0;
      clients.forEach((d, ws) => {
        send(ws, { type: 'chat_message', text: `📢 ADMIN: ${data.message}`, from: 'system' });
        count++;
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, sent: count }));
    } else {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Message required' }));
    }
    return;
  }

  // Admin give coins to a user
  if (req.url === '/admin/give-coins' && req.method === 'POST') {
    const data = await readBody(req);
    let coinKey = null;
    let label = '';

    // Resolve coin key from various inputs
    if (data.coinKey) {
      coinKey = data.coinKey;
      label = coinKey;
    } else if (data.username) {
      // Look up by username - check accounts first
      const acc = getAccountByUsername(data.username);
      if (acc) {
        coinKey = `g:${acc.googleId}`;
        label = data.username;
      } else {
        // Fall back to IP-based username lookup
        const ipForUser = coinsData.usernames ? Object.entries(coinsData.usernames).find(([_, name]) => name.toLowerCase() === data.username.toLowerCase()) : null;
        if (ipForUser) { coinKey = ipForUser[0]; label = data.username; }
      }
    } else if (data.ip) {
      coinKey = data.ip;
      label = data.ip.slice(0, 8) + '***';
    }

    if (coinKey && data.amount > 0) {
      addCoins(coinKey, data.amount, `Admin gift: ${data.amount} coins`);
      // Notify user if online
      clients.forEach((d, ws) => {
        if (getCoinKey(d) === coinKey) send(ws, { type: 'coins_updated', balance: getBalance(coinKey) });
      });
      console.log(`[ADMIN] Gave ${data.amount} coins to ${label}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, balance: getBalance(coinKey) }));
    } else {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Valid target and amount required' }));
    }
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
  const myPerks = getUserPerks(getCoinKey(d));
  const myRegion = myPerks.region || 'any';
  const myMode = d.mode || 'video';

  let best = null, bestScore = -1;
  for (let i = 0; i < waitingQueue.length; i++) {
    const c = waitingQueue[i];
    if (c === ws || c.readyState !== 1) continue;
    const cd = clients.get(c);
    if (!cd || cd.partner) continue;
    // Mode filter: only match same mode (video↔video, text↔text)
    if ((cd.mode || 'video') !== myMode) continue;
    const theirPerks = getUserPerks(getCoinKey(cd));
    const theirRegion = theirPerks.region || 'any';
    if (myRegion !== 'any' && theirRegion !== 'any' && myRegion !== theirRegion) continue;
    if (myRegion !== 'any' && theirRegion === 'any') { /* ok, they accept anyone */ }
    if (myRegion === 'any' && theirRegion !== 'any') { /* ok, we accept anyone */ }
    const score = calculateMatchScore(d.interests, cd.interests);
    if (score > bestScore) { bestScore = score; best = { index: i, ws: c, score }; }
  }
  if (!best) {
    for (let i = 0; i < waitingQueue.length; i++) {
      const c = waitingQueue[i];
      if (c === ws || c.readyState !== 1) continue;
      const cd = clients.get(c);
      if (!cd || cd.partner) continue;
      if ((cd.mode || 'video') !== myMode) continue;
      const theirPerks = getUserPerks(getCoinKey(cd));
      const theirRegion = theirPerks.region || 'any';
      if (myRegion !== 'any' && theirRegion !== 'any' && myRegion !== theirRegion) continue;
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
  const p1 = getUserPerks(getCoinKey(d1));
  const p2 = getUserPerks(getCoinKey(d2));

  // Send matched to real users only (not bots)
  if (!d1.isBot) {
    send(ws1, { type: 'matched', role: 'initiator', sharedInterests: shared, partnerId: d2.id,
      partnerUsername: d2.username || 'Stranger', partnerPerks: { nameColor: p2.nameColor, bubbleTheme: p2.bubbleTheme, entrance: p2.entrance },
      partnerSignedIn: !!d2.googleId });
  }
  if (!d2.isBot) {
    send(ws2, { type: 'matched', role: 'receiver', sharedInterests: shared, partnerId: d1.id,
      partnerUsername: d1.username || 'Stranger', partnerPerks: { nameColor: p1.nameColor, bubbleTheme: p1.bubbleTheme, entrance: p1.entrance },
      partnerSignedIn: !!d1.googleId });
  }

  // Bot sends greeting after a short delay
  const botEntry = d1.isBot ? { botWs: ws1, humanWs: ws2, botData: d1 } : d2.isBot ? { botWs: ws2, humanWs: ws1, botData: d2 } : null;
  if (botEntry && !botEntry.botData.greeted) {
    botEntry.botData.greeted = true;
    const greeting = botEntry.botData.persona.greetings[Math.floor(Math.random() * botEntry.botData.persona.greetings.length)];
    setTimeout(() => {
      const bd = clients.get(botEntry.botWs);
      if (bd && bd.partner === botEntry.humanWs) {
        send(botEntry.humanWs, { type: 'chat_message', text: greeting, from: 'stranger' });
      }
    }, 1500 + Math.random() * 2000);
  }

  // Track recent partners for reconnect
  addRecentPartner(d1.ip, d2.id, d2.ip);
  addRecentPartner(d2.ip, d1.id, d1.ip);
  console.log(`[PAIR] ${d1.username || d1.id} <-> ${d2.username || d2.id}`);
}

function removeFromQueue(ws) { const i = waitingQueue.indexOf(ws); if (i !== -1) waitingQueue.splice(i, 1); }

function unpairUser(ws) {
  const d = clients.get(ws);
  if (!d || !d.partner) return;
  const partner = d.partner;
  const pd = clients.get(partner);
  if (pd) {
    connectedPairs.delete([d.id, pd.id].sort().join(':'));
    pd.partner = null;
    if (!pd.isBot) {
      send(partner, { type: 'partner_disconnected' });
    } else {
      // Re-queue the bot after a delay
      pd.greeted = false;
      pd.messageCount = 0;
      pd.maxMessages = 8 + Math.floor(Math.random() * 15);
      setTimeout(() => {
        if (clients.has(partner) && !pd.partner) waitingQueue.push(partner);
      }, 2000 + Math.random() * 3000);
    }
  }
  d.partner = null;
}

function send(ws, data) { if (ws.readyState === 1) ws.send(JSON.stringify(data)); }

function disconnectAndBan(ws, reason) {
  const d = clients.get(ws);
  if (!d) return;
  const token = banIP(d.ip, reason, d.username, d.googleId);
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

  clients.set(ws, { id, ip, interests: [], partner: null, alive: true, warnings: 0, username: '', googleId: null, mode: 'video' });
  send(ws, { type: 'welcome', id, online: clients.size });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const cd = clients.get(ws);
    if (!cd) return;

    if (isUserBanned(cd.ip, cd.googleId)) {
      const info = getBanInfo(cd.ip);
      const reason = info?.reason || (banData.bannedGoogleIds?.[cd.googleId]?.reason) || 'Banned';
      send(ws, { type: 'banned', reason, unbanToken: info?.unbanToken || '' });
      ws.close(); return;
    }

    switch (msg.type) {
      case 'join_queue': {
        unpairUser(ws); removeFromQueue(ws);
        cd.interests = Array.isArray(msg.interests) ? msg.interests.slice(0, 10) : [];
        cd.username = typeof msg.username === 'string' ? msg.username.slice(0, 20).replace(/[^a-zA-Z0-9_]/g, '') : '';
        if (msg.googleId) cd.googleId = msg.googleId;
        if (msg.mode === 'video' || msg.mode === 'text') cd.mode = msg.mode;
        if (cd.username) setUsername(cd.ip, cd.username);
        // Send coins/perks now that googleId is known
        const ck = getCoinKey(cd);
        send(ws, { type: 'coins_updated', balance: getBalance(ck) });
        send(ws, { type: 'perks_updated', perks: getUserPerks(ck), balance: getBalance(ck) });
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
          // Check if partner is a bot
          const partnerData = clients.get(cd.partner);
          if (partnerData && partnerData.isBot) {
            handleBotMessage(cd.partner, ws, text);
          } else {
            send(cd.partner, { type: 'chat_message', text, from: 'stranger' });
          }
        }
        break;
      }
      case 'skip': {
        unpairUser(ws);
        cd.interests = Array.isArray(msg.interests) ? msg.interests.slice(0, 10) : cd.interests;
        if (typeof msg.username === 'string') { cd.username = msg.username.slice(0, 20).replace(/[^a-zA-Z0-9_]/g, ''); if (cd.username) setUsername(cd.ip, cd.username); }
        if (msg.googleId) cd.googleId = msg.googleId;
        if (msg.mode === 'video' || msg.mode === 'text') cd.mode = msg.mode;
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
      // ─── Send Gift ───
      case 'send_gift': {
        if (cd.partner && typeof msg.giftId === 'string') {
          const gift = GIFTS[msg.giftId];
          if (!gift) break;
          if (!spendCoins(getCoinKey(cd), gift.cost)) {
            send(ws, { type: 'gift_error', message: 'Not enough M Coins!' });
            break;
          }
          // Credit coins to the receiver
          const pd = clients.get(cd.partner);
          if (pd) {
            addCoins(getCoinKey(pd), gift.cost, `Gift from ${cd.username || 'stranger'}: ${gift.name}`);
            trackGiftReceived(pd.ip, gift.cost);
            // Notify receiver of updated balance
            send(cd.partner, { type: 'coins_updated', balance: getBalance(getCoinKey(pd)) });
          }
          coinsData.totalGifts = (coinsData.totalGifts || 0) + 1;
          saveCoins();
          // Send animation to both
          const giftMsg = { type: 'gift_received', giftId: msg.giftId, emoji: gift.emoji, name: gift.name, cost: gift.cost, from: cd.username || 'stranger' };
          send(cd.partner, giftMsg);
          send(ws, { type: 'gift_sent', giftId: msg.giftId, emoji: gift.emoji, name: gift.name, cost: gift.cost, balance: getBalance(getCoinKey(cd)) });
          console.log(`[GIFT] ${cd.username || cd.id} sent ${gift.name} (${gift.cost} coins) to ${pd?.username || 'stranger'}`);
        }
        break;
      }

      // ─── Reconnect with last partner ───
      case 'reconnect': {
        const cost = PERKS.reconnectCost;
        if (!spendCoins(getCoinKey(cd), cost)) {
          send(ws, { type: 'gift_error', message: `Need ${cost} M Coins to reconnect!` });
          break;
        }
        send(ws, { type: 'coins_updated', balance: getBalance(getCoinKey(cd)) });
        const recent = getRecentPartners(cd.ip);
        if (recent.length === 0) {
          addCoins(getCoinKey(cd), cost, 'Reconnect refund - no history');
          send(ws, { type: 'gift_error', message: 'No recent partners to reconnect with.' });
          send(ws, { type: 'coins_updated', balance: getBalance(getCoinKey(cd)) });
          break;
        }
        // Try to find the most recent partner who is online and not paired
        let found = false;
        for (const p of recent) {
          for (const [pws, pd] of clients.entries()) {
            if (pd.ip === p.ip && !pd.partner && pws !== ws) {
              unpairUser(ws); removeFromQueue(ws);
              pairUsers(ws, pws);
              found = true;
              break;
            }
          }
          if (found) break;
        }
        if (!found) {
          addCoins(getCoinKey(cd), cost, 'Reconnect refund - partner offline');
          send(ws, { type: 'coins_updated', balance: getBalance(getCoinKey(cd)) });
          send(ws, { type: 'gift_error', message: 'Your last partner is not available right now.' });
        }
        break;
      }

      // ─── Set Google ID for WS connection ───
      case 'set_google_id': {
        if (msg.googleId) cd.googleId = msg.googleId;
        break;
      }

      // ─── DM via WebSocket ───
      case 'dm_message': {
        if (!cd.googleId || !msg.toUsername || !msg.text) break;
        const targetAcc = getAccountByUsername(msg.toUsername);
        if (!targetAcc) break;
        // Save DM
        saveDM(cd.googleId, targetAcc.googleId, msg.text.slice(0, 500));
        // Deliver in real-time if target is online
        clients.forEach((d, w) => {
          if (d.googleId === targetAcc.googleId) {
            send(w, { type: 'dm_incoming', fromUsername: cd.username, text: msg.text.slice(0, 500) });
          }
        });
        break;
      }

      // ─── Get Balance via WS ───
      case 'get_balance': {
        send(ws, { type: 'coins_updated', balance: getBalance(getCoinKey(cd)) });
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
  const realCount = clients.size;
  const botCount = activeBots.size;
  const displayCount = realCount + Math.floor(botCount * 0.5); // Show partial bot count
  wss.clients.forEach(ws => send(ws, { type: 'online_count', count: displayCount }));
}, 5000);

// ═══════════════════════════════════════════
// BOT SYSTEM (TEXT CHAT ONLY)
// ═══════════════════════════════════════════
const BOT_PERSONAS = [
  { name: 'Luna', interests: ['music', 'movies', 'art'], greetings: ['hey!', 'hii', 'whats up!', 'heyyy', 'hola!'], personality: 'chill' },
  { name: 'Jake', interests: ['gaming', 'sports', 'tech'], greetings: ['yo', 'hey', 'sup', 'whats good', 'heyy'], personality: 'casual' },
  { name: 'Sophie', interests: ['travel', 'food', 'photography'], greetings: ['hi there!', 'hello!', 'heyyy', 'hey how are you'], personality: 'friendly' },
  { name: 'Alex', interests: ['anime', 'gaming', 'music'], greetings: ['yoo', 'hey!', 'hi', 'hii whats up', 'heyo'], personality: 'energetic' },
  { name: 'Maya', interests: ['books', 'art', 'music', 'movies'], greetings: ['hi!', 'hello', 'hey there', 'heyy'], personality: 'thoughtful' },
  { name: 'Tyler', interests: ['sports', 'fitness', 'gaming'], greetings: ['sup', 'yo whats up', 'hey', 'whats good'], personality: 'bro' },
  { name: 'Zoe', interests: ['fashion', 'travel', 'food', 'music'], greetings: ['hiii', 'heyyy!', 'omg hi', 'hello!'], personality: 'bubbly' },
  { name: 'Kai', interests: ['tech', 'science', 'gaming', 'anime'], greetings: ['hey', 'hi', 'yo', 'hello there'], personality: 'nerdy' },
  { name: 'Emma', interests: ['movies', 'cooking', 'travel'], greetings: ['hi!', 'hey!', 'hello :)', 'hii'], personality: 'warm' },
  { name: 'Ryan', interests: ['music', 'sports', 'cars'], greetings: ['yo', 'hey man', 'sup', 'whats up'], personality: 'laid-back' },
];

const BOT_RESPONSES = {
  chill: {
    generic: ['oh nice', 'thats cool', 'lol', 'hmm yeah', 'for real', 'i feel that', 'same honestly', 'thats awesome', 'oh really?', 'haha yeah'],
    question: ['wbu?', 'what about you?', 'do you?', 'have you?', 'really?'],
    topics: ['so what do you do for fun?', 'where are you from?', 'whats your fav music?', 'watched anything good lately?', 'you into any hobbies?'],
    farewell: ['gotta go, nice talking!', 'cya!', 'was fun chatting, bye!', 'catch you later!'],
  },
  casual: {
    generic: ['nice', 'thats sick', 'no way', 'haha', 'oh word', 'thats dope', 'for sure', 'lol yeah', 'true true', 'bet'],
    question: ['you?', 'wbu?', 'same?', 'fr?', 'really tho?'],
    topics: ['you play any games?', 'what music you into?', 'where you from?', 'you watch sports?', 'got any plans this weekend?'],
    farewell: ['ight im out, peace', 'later!', 'gotta bounce, nice chat', 'peace out!'],
  },
  friendly: {
    generic: ['oh thats so cool!', 'I love that!', 'thats amazing', 'aw thats nice', 'wow really?', 'haha thats funny', 'oh nice!', 'so cool', 'I totally agree'],
    question: ['what about you?', 'have you tried that?', 'do you like that too?', 'whats yours?'],
    topics: ['so tell me about yourself!', 'whats the best trip youve taken?', 'do you cook?', 'whats your dream vacation?', 'any pets?'],
    farewell: ['it was so nice talking to you!', 'bye! have a great day!', 'gotta run, take care!', 'lovely chatting with you!'],
  },
  energetic: {
    generic: ['YOOO', 'thats so fire', 'no wayy', 'haha thats great', 'omg', 'lets gooo', 'sickk', 'bro thats awesome', 'W', 'lmaooo'],
    question: ['you too?', 'fr??', 'wait really?', 'no cap?'],
    topics: ['bro you gotta watch this anime', 'whats your top game rn?', 'you listen to any good music lately?', 'whats your go-to snack?'],
    farewell: ['yo gotta go, was fire chatting!', 'laterrr!', 'peace!! was fun', 'ight catch you around!'],
  },
  thoughtful: {
    generic: ['hmm interesting', 'I can see that', 'thats a good point', 'oh I like that', 'yeah I think so too', 'thats really cool actually', 'mmm yeah'],
    question: ['what makes you say that?', 'how did you get into that?', 'what do you think about it?', 'whats your take?'],
    topics: ['read any good books lately?', 'what kind of art do you like?', 'if you could go anywhere, where?', 'whats something youre passionate about?'],
    farewell: ['this was a nice conversation, thank you!', 'I enjoyed this chat, bye!', 'take care, it was lovely talking!'],
  },
  bro: {
    generic: ['bro thats sick', 'no way dude', 'haha facts', 'thats lit', 'W bro', 'nah fr', 'goated', 'ong', 'valid', 'lol'],
    question: ['you lift?', 'fr?', 'what team you support?', 'you?'],
    topics: ['you into any sports?', 'hit the gym today?', 'what games you play?', 'bro whats your workout split?'],
    farewell: ['ight bro gotta go, stay hard', 'laterr bro', 'peace out dude', 'catch you later man'],
  },
  bubbly: {
    generic: ['omg yesss', 'I love that so much!', 'aw thats adorable', 'haha sameee', 'noo wayyyy', 'stoppp thats amazing', 'yesss queen', 'lolol', 'literally me'],
    question: ['OMG same?? you too?', 'wait really??', 'tell me moree!', 'whats yours?'],
    topics: ['ok but whats your fav food??', 'have you traveled anywhere fun?', 'whats your aesthetic?', 'besttt song right now?'],
    farewell: ['byeee it was so fun talking!!', 'gotta go love, byee!', 'this was so fun!! cya!', 'muah bye!!'],
  },
  nerdy: {
    generic: ['oh thats interesting', 'I didnt know that', 'huh cool', 'yeah that makes sense', 'nice', 'I agree', 'thats fair', 'good point'],
    question: ['how so?', 'why do you think that?', 'what got you into that?', 'do you know about...?'],
    topics: ['whats your fav programming language?', 'you into space stuff?', 'played any good RPGs?', 'any tech you find interesting?', 'you seen any good sci fi?'],
    farewell: ['gotta log off, nice chat', 'was good talking, bye', 'catch you later!', 'signing off, take care'],
  },
  warm: {
    generic: ['aw thats nice!', 'haha yes!', 'I love that', 'oh how fun!', 'thats really sweet', 'oh nice!', 'hehe', 'aww', 'that sounds great!'],
    question: ['ooh whats yours?', 'really? tell me more!', 'how about you?', 'you like that too?'],
    topics: ['whats your comfort food?', 'do you have any hobbies?', 'watched any good movies lately?', 'whats making you happy lately?'],
    farewell: ['gotta go, it was really nice talking!', 'bye bye, take care!', 'lovely chat, have a good one!'],
  },
  'laid-back': {
    generic: ['yeah man', 'chill', 'nice nice', 'haha true', 'sounds good', 'thats cool', 'for sure', 'i dig it', 'right on'],
    question: ['you into that?', 'what about you?', 'you heard of it?', 'same?'],
    topics: ['what kinda music you into?', 'do you follow any sports?', 'whats your dream car?', 'you play any instruments?'],
    farewell: ['peace, was chill talking', 'later man', 'take it easy, cya', 'gotta roll, peace'],
  },
};

const activeBots = new Map(); // botId -> botData
const BOT_MIN = 3;  // Minimum bots always active
const BOT_MAX = 8;  // Maximum bots

// Fake WebSocket-like object for bots
class BotSocket {
  constructor(id) { this.id = id; this.readyState = 1; this._partner = null; }
  send() {} // Bots don't actually receive WebSocket messages
  close() { this.readyState = 3; }
  terminate() { this.readyState = 3; }
}

function createBot() {
  const persona = BOT_PERSONAS[Math.floor(Math.random() * BOT_PERSONAS.length)];
  const botId = `bot_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
  const botWs = new BotSocket(botId);

  const botData = {
    id: botId,
    ip: `bot_${botId}`,
    interests: persona.interests.slice(0, 2 + Math.floor(Math.random() * 2)),
    partner: null,
    alive: true,
    warnings: 0,
    username: persona.name,
    googleId: null,
    mode: 'text', // Bots only in text chat
    isBot: true,
    persona: persona,
    messageCount: 0,
    maxMessages: 8 + Math.floor(Math.random() * 15), // 8-22 messages per conversation
    lastMsgTime: 0,
    greeted: false,
  };

  clients.set(botWs, botData);
  activeBots.set(botId, { ws: botWs, data: botData });

  // Add to text queue
  waitingQueue.push(botWs);
  console.log(`[BOT] ${persona.name} joined text chat queue`);
  return botWs;
}

function removeBotCleanly(botId) {
  const bot = activeBots.get(botId);
  if (!bot) return;
  const { ws, data } = bot;

  // If bot has a partner, notify them
  if (data.partner) {
    const partnerData = clients.get(data.partner);
    if (partnerData) {
      send(data.partner, { type: 'partner_disconnected' });
      partnerData.partner = null;
    }
  }

  removeFromQueue(ws);
  clients.delete(ws);
  activeBots.delete(botId);
  ws.close();
}

function getBotResponse(persona, userMessage) {
  const responses = BOT_RESPONSES[persona.personality];
  if (!responses) return 'haha yeah';

  const lower = userMessage.toLowerCase();

  // Respond to questions
  if (lower.includes('?') || lower.includes('wbu') || lower.includes('you?') || lower.includes('about you')) {
    // Topical answers
    if (lower.includes('name') || lower.includes('who are you')) return `im ${persona.name}!`;
    if (lower.includes('where') || lower.includes('from')) {
      const places = ['US', 'Canada', 'UK', 'somewhere in Europe', 'Cali', 'New York', 'Texas', 'Florida', 'Chicago'];
      return places[Math.floor(Math.random() * places.length)];
    }
    if (lower.includes('age') || lower.includes('old are')) {
      return `${17 + Math.floor(Math.random() * 8)} haha`;
    }
    if (lower.includes('hobby') || lower.includes('fun') || lower.includes('do for')) {
      return `i really like ${persona.interests[Math.floor(Math.random() * persona.interests.length)]}! ${responses.question[Math.floor(Math.random() * responses.question.length)]}`;
    }
    // Generic question response
    const r = responses.generic[Math.floor(Math.random() * responses.generic.length)];
    return r + ' ' + responses.question[Math.floor(Math.random() * responses.question.length)];
  }

  // Greetings
  if (['hi', 'hey', 'hello', 'hii', 'heyy', 'heyyy', 'yo', 'sup', 'whats up', 'hola'].some(g => lower.startsWith(g))) {
    const greeting = persona.greetings[Math.floor(Math.random() * persona.greetings.length)];
    if (Math.random() > 0.5) return greeting + ' ' + responses.question[Math.floor(Math.random() * responses.question.length)];
    return greeting;
  }

  // Topic starters (sometimes ask a question back)
  if (Math.random() < 0.3) {
    return responses.topics[Math.floor(Math.random() * responses.topics.length)];
  }

  // Generic response
  const gen = responses.generic[Math.floor(Math.random() * responses.generic.length)];
  if (Math.random() < 0.35) {
    return gen + ' ' + responses.question[Math.floor(Math.random() * responses.question.length)];
  }
  return gen;
}

// Handle messages sent TO a bot
function handleBotMessage(botWs, fromWs, text) {
  const botData = clients.get(botWs);
  if (!botData || !botData.isBot) return;

  botData.messageCount++;

  // If max messages reached, bot "skips"
  if (botData.messageCount >= botData.maxMessages) {
    setTimeout(() => {
      const bd = clients.get(botWs);
      if (bd && bd.partner) {
        send(bd.partner, { type: 'partner_disconnected' });
        const partnerData = clients.get(bd.partner);
        if (partnerData) partnerData.partner = null;
        bd.partner = null;
        bd.messageCount = 0;
        bd.maxMessages = 8 + Math.floor(Math.random() * 15);
        bd.greeted = false;
        // Re-queue the bot
        waitingQueue.push(botWs);
      }
    }, 1000 + Math.random() * 2000);
    return;
  }

  // Generate response with realistic delay
  const delay = 800 + Math.random() * 2500; // 0.8-3.3 seconds
  setTimeout(() => {
    const bd = clients.get(botWs);
    if (!bd || !bd.partner || bd.partner !== fromWs) return;
    const response = getBotResponse(bd.persona, text);
    send(fromWs, { type: 'chat_message', text: response, from: 'stranger' });
  }, delay);
}

// Bot management loop
setInterval(() => {
  // Remove stale bots
  activeBots.forEach((bot, botId) => {
    const d = clients.get(bot.ws);
    if (!d) { activeBots.delete(botId); return; }
  });

  // Ensure minimum bots exist
  const currentBots = activeBots.size;
  if (currentBots < BOT_MIN) {
    const toCreate = BOT_MIN - currentBots;
    for (let i = 0; i < toCreate; i++) createBot();
  }

  // Add more bots if few real users are waiting in text queue
  const textWaiting = waitingQueue.filter(ws => {
    const d = clients.get(ws);
    return d && d.mode === 'text' && !d.isBot;
  }).length;

  if (textWaiting > 0 && activeBots.size < BOT_MAX) {
    createBot(); // Add a bot to match with waiting user
  }

  // Remove excess idle bots (not paired)
  if (activeBots.size > BOT_MAX) {
    let removed = 0;
    activeBots.forEach((bot, botId) => {
      if (removed >= activeBots.size - BOT_MAX) return;
      const d = clients.get(bot.ws);
      if (d && !d.partner) {
        removeBotCleanly(botId);
        removed++;
      }
    });
  }
}, 5000);

// Start initial bots
setTimeout(() => {
  for (let i = 0; i < BOT_MIN; i++) createBot();
  console.log(`[BOT] Started ${BOT_MIN} initial chat bots`);
}, 2000);

// ─── Start ───
server.listen(PORT, () => {
  console.log(`MingleNow server on port ${PORT}`);
  console.log(`Active bans: ${Object.keys(banData.bannedIPs).filter(ip => !banData.bannedIPs[ip].paid).length}`);
});
