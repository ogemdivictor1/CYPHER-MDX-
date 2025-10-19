const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const { makeWASocket, useMultiFileAuthState, Browsers, DisconnectReason, delay } = require('@whiskeysockets/baileys');
const P = require('pino');
const { nanoid } = require('nanoid');

// --- Config ---
const PORT = process.env.PORT || 10000;
const PASSWORD = 'CypherDeals';
const BADWORDS_FILE = path.join(__dirname, 'badwords.json');

// Load bad words
const badWords = JSON.parse(fs.readFileSync(BADWORDS_FILE, 'utf8')).badWords.map(w => w.toLowerCase());

// --- Express + Socket.IO setup ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- Session storage ---
const sessions = {};
const warnings = {};

// --- Helpers ---
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

ensureDir(path.join(__dirname, 'sessions'));

// --- Auth middleware ---
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === PASSWORD) {
    const hash = crypto.createHash('sha256').update(PASSWORD).digest('hex');
    res.cookie('auth', hash, { httpOnly: true });
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, message: 'Wrong password' });
});

function auth(req, res, next) {
  const c = req.cookies.auth;
  const valid = crypto.createHash('sha256').update(PASSWORD).digest('hex');
  if (c === valid) return next();
  res.status(401).json({ ok: false, message: 'Unauthorized' });
}

// --- Start or reconnect socket ---
async function startSock(sessionId, number) {
  const sessionPath = path.join(__dirname, 'sessions', sessionId);
  ensureDir(sessionPath);

  try {
    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);

    const sock = makeWASocket({
      auth: state,
      printQRInTerminal: false,
      logger: P({ level: 'silent' }),
      browser: Browsers.macOS('Cypher MDX')
    });

    sessions[sessionId] = sock;
    warnings[sessionId] = warnings[sessionId] || {};

    sock.ev.on('creds.update', saveCreds);

    // Connection updates
    sock.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect, pairingCode } = update;

      if (pairingCode) {
        // Emit pairing code to frontend
        io.to(sessionId).emit('pairing', { code: pairingCode });
      }

      if (connection === 'open') io.to(sessionId).emit('connected', {});

      if (connection === 'close') {
        const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
        if (shouldReconnect) {
          console.log('🔁 Reconnecting session', sessionId);
          setTimeout(() => startSock(sessionId, number), 5000);
        } else {
          io.to(sessionId).emit('disconnected', {});
        }
      }
    });

    // Messages events
    sock.ev.on('messages.upsert', async ({ messages }) => {
      const msg = messages[0];
      if (!msg.message || msg.key.fromMe) return;

      const text = msg.message.conversation || msg.message.extendedTextMessage?.text || '';
      const from = msg.key.remoteJid;
      const sender = msg.key.participant || msg.key.remoteJid;

      const containsBadWord = badWords.some(word => text.toLowerCase().includes(word));
      const containsLink = /(https?:\/\/|www\.)\S+/i.test(text);

      if (containsBadWord || containsLink) {
        const jid = sender;
        warnings[sessionId][jid] = (warnings[sessionId][jid] || 0) + 1;
        const count = warnings[sessionId][jid];

        await sock.sendMessage(from, {
          text: `⚠️ @${jid.split('@')[0]}, warning ${count}/3: stop sending links or vulgar words!`,
          mentions: [jid]
        });

        await delay(500);
        await sock.sendMessage(from, { delete: msg.key });

        if (count >= 3) {
          try {
            await sock.groupParticipantsUpdate(from, [jid], 'remove');
            await sock.sendMessage(from, {
              text: `🚫 @${jid.split('@')[0]} has been removed after 3 warnings.`,
              mentions: [jid]
            });
          } catch (err) {
            console.log('Kick error:', err);
          }
        }

        io.to(sessionId).emit('warnings', warnings[sessionId]);
      }
    });

    return sock;
  } catch (err) {
    console.error('Failed to start session:', err);
    throw err;
  }
}

// --- API to create session ---
app.post('/api/create-session', auth, async (req, res) => {
  const number = req.body.number || 'unknown';
  const sessionId = nanoid(8);

  const sessionPath = path.join(__dirname, 'sessions', sessionId);
  ensureDir(sessionPath);

  fs.writeFileSync(path.join(sessionPath, 'info.json'), JSON.stringify({ number, created: new Date() }, null, 2));

  try {
    await startSock(sessionId, number);
    res.json({ ok: true, sessionId });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Failed to create session' });
  }
});

// --- API to get warnings ---
app.get('/api/warnings/:sid', auth, (req, res) => {
  const sid = req.params.sid;
  res.json(warnings[sid] || {});
});

// --- Socket.IO connection ---
io.on('connection', (socket) => {
  socket.on('join-session', (data) => {
    const { sessionId } = data;
    if (sessionId) socket.join(sessionId);
  });
});

// --- Start server ---
server.listen(PORT, () => {
  console.log(`⚡ Cypher MDX running on port ${PORT}`);
});
