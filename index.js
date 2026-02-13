const { WebSocketServer } = require('ws');
const http = require('http');

// ─── Config ───
const PORT = process.env.PORT || 3001;
const HEARTBEAT_INTERVAL = 30000;

// ─── Server Setup ───
const server = http.createServer((req, res) => {
  // Health check endpoint
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      waiting: waitingQueue.length,
      connected: connectedPairs.size,
      online: clients.size
    }));
    return;
  }

  // CORS preflight
  res.writeHead(200, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
  });
  res.end('MingleNow Signaling Server');
});

const wss = new WebSocketServer({ server });

// ─── State ───
const clients = new Map();       // ws -> { id, interests, partner, alive }
const waitingQueue = [];         // [ws, ws, ...]
const connectedPairs = new Set(); // Set of "id1:id2" strings
const reportLog = [];            // [{ reporter, reported, reason, timestamp }]
let nextId = 1;

function generateId() {
  return `user_${nextId++}_${Date.now().toString(36)}`;
}

// ─── Interest Matching ───
function calculateMatchScore(interests1, interests2) {
  if (!interests1.length || !interests2.length) return 0;
  const set1 = new Set(interests1.map(i => i.toLowerCase().trim()));
  let matches = 0;
  for (const interest of interests2) {
    if (set1.has(interest.toLowerCase().trim())) matches++;
  }
  return matches;
}

function findBestMatch(ws) {
  const clientData = clients.get(ws);
  if (!clientData) return null;

  let bestMatch = null;
  let bestScore = -1;

  for (let i = 0; i < waitingQueue.length; i++) {
    const candidate = waitingQueue[i];
    if (candidate === ws) continue;
    if (candidate.readyState !== 1) continue;

    const candidateData = clients.get(candidate);
    if (!candidateData || candidateData.partner) continue;

    const score = calculateMatchScore(clientData.interests, candidateData.interests);

    if (score > bestScore) {
      bestScore = score;
      bestMatch = { index: i, ws: candidate, score };
    }
  }

  // If no interest match found, take the first available person
  if (!bestMatch && waitingQueue.length > 0) {
    for (let i = 0; i < waitingQueue.length; i++) {
      const candidate = waitingQueue[i];
      if (candidate === ws) continue;
      if (candidate.readyState !== 1) continue;
      const candidateData = clients.get(candidate);
      if (!candidateData || candidateData.partner) continue;
      bestMatch = { index: i, ws: candidate, score: 0 };
      break;
    }
  }

  return bestMatch;
}

// ─── Pair Two Users ───
function pairUsers(ws1, ws2) {
  const data1 = clients.get(ws1);
  const data2 = clients.get(ws2);
  if (!data1 || !data2) return;

  data1.partner = ws2;
  data2.partner = ws1;

  const pairId = [data1.id, data2.id].sort().join(':');
  connectedPairs.add(pairId);

  // Remove both from waiting queue
  removeFromQueue(ws1);
  removeFromQueue(ws2);

  // Calculate shared interests
  const shared = [];
  if (data1.interests.length && data2.interests.length) {
    const set1 = new Set(data1.interests.map(i => i.toLowerCase().trim()));
    for (const interest of data2.interests) {
      if (set1.has(interest.toLowerCase().trim())) shared.push(interest);
    }
  }

  // Notify both users — ws1 is the "initiator" (creates offer)
  send(ws1, {
    type: 'matched',
    role: 'initiator',
    sharedInterests: shared,
    partnerId: data2.id,
  });

  send(ws2, {
    type: 'matched',
    role: 'receiver',
    sharedInterests: shared,
    partnerId: data1.id,
  });

  console.log(`[PAIR] ${data1.id} <-> ${data2.id} (shared: ${shared.join(', ') || 'none'})`);
}

function removeFromQueue(ws) {
  const idx = waitingQueue.indexOf(ws);
  if (idx !== -1) waitingQueue.splice(idx, 1);
}

function unpairUser(ws) {
  const data = clients.get(ws);
  if (!data || !data.partner) return;

  const partnerWs = data.partner;
  const partnerData = clients.get(partnerWs);

  // Remove pair record
  if (partnerData) {
    const pairId = [data.id, partnerData.id].sort().join(':');
    connectedPairs.delete(pairId);
    partnerData.partner = null;
    send(partnerWs, { type: 'partner_disconnected' });
  }

  data.partner = null;
}

function send(ws, data) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(data));
  }
}

// ─── WebSocket Handler ───
wss.on('connection', (ws) => {
  const id = generateId();
  clients.set(ws, { id, interests: [], partner: null, alive: true });

  send(ws, { type: 'welcome', id, online: clients.size });

  console.log(`[CONNECT] ${id} (online: ${clients.size})`);

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    const clientData = clients.get(ws);
    if (!clientData) return;

    switch (msg.type) {

      // ─── Join Queue ───
      case 'join_queue': {
        // Unpair if currently paired
        unpairUser(ws);
        removeFromQueue(ws);

        clientData.interests = Array.isArray(msg.interests) ? msg.interests.slice(0, 10) : [];

        // Try to find a match immediately
        const match = findBestMatch(ws);
        if (match) {
          pairUsers(ws, match.ws);
        } else {
          waitingQueue.push(ws);
          send(ws, { type: 'waiting', position: waitingQueue.length });
          console.log(`[QUEUE] ${clientData.id} waiting (queue: ${waitingQueue.length})`);
        }
        break;
      }

      // ─── Leave Queue ───
      case 'leave_queue': {
        removeFromQueue(ws);
        send(ws, { type: 'left_queue' });
        break;
      }

      // ─── WebRTC Signaling ───
      case 'rtc_offer':
      case 'rtc_answer':
      case 'rtc_ice_candidate': {
        if (clientData.partner) {
          send(clientData.partner, msg);
        }
        break;
      }

      // ─── Text Message ───
      case 'chat_message': {
        if (clientData.partner && typeof msg.text === 'string') {
          const sanitized = msg.text.slice(0, 500).trim();
          if (sanitized) {
            send(clientData.partner, {
              type: 'chat_message',
              text: sanitized,
              from: 'stranger',
            });
          }
        }
        break;
      }

      // ─── Skip / Next ───
      case 'skip': {
        unpairUser(ws);
        // Automatically rejoin queue
        clientData.interests = Array.isArray(msg.interests) ? msg.interests.slice(0, 10) : clientData.interests;
        const match = findBestMatch(ws);
        if (match) {
          pairUsers(ws, match.ws);
        } else {
          waitingQueue.push(ws);
          send(ws, { type: 'waiting', position: waitingQueue.length });
        }
        break;
      }

      // ─── Report User ───
      case 'report': {
        if (clientData.partner) {
          const partnerData = clients.get(clientData.partner);
          if (partnerData) {
            reportLog.push({
              reporter: clientData.id,
              reported: partnerData.id,
              reason: typeof msg.reason === 'string' ? msg.reason.slice(0, 200) : 'no reason',
              timestamp: new Date().toISOString(),
            });
            console.log(`[REPORT] ${clientData.id} reported ${partnerData.id}: ${msg.reason}`);
            send(ws, { type: 'report_confirmed' });
            // Disconnect the pair
            unpairUser(ws);
          }
        }
        break;
      }

      // ─── Heartbeat ───
      case 'pong': {
        clientData.alive = true;
        break;
      }
    }
  });

  ws.on('close', () => {
    console.log(`[DISCONNECT] ${clientData?.id || 'unknown'} (online: ${clients.size - 1})`);
    unpairUser(ws);
    removeFromQueue(ws);
    clients.delete(ws);
  });

  ws.on('error', () => {
    unpairUser(ws);
    removeFromQueue(ws);
    clients.delete(ws);
  });
});

// ─── Heartbeat to detect dead connections ───
setInterval(() => {
  wss.clients.forEach((ws) => {
    const data = clients.get(ws);
    if (!data) return;
    if (!data.alive) {
      ws.terminate();
      return;
    }
    data.alive = false;
    send(ws, { type: 'ping' });
  });
}, HEARTBEAT_INTERVAL);

// ─── Broadcast online count every 5s ───
setInterval(() => {
  const count = clients.size;
  wss.clients.forEach((ws) => {
    send(ws, { type: 'online_count', count });
  });
}, 5000);

// ─── Start ───
server.listen(PORT, () => {
  console.log(`MingleNow signaling server running on port ${PORT}`);
});
