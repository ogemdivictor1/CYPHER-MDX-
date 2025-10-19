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

// Load bad words list
const BADWORDS_FILE = path.join(__dirname, 'badwords.json');
const badWords = JSON.parse(fs.readFileSync(BADWORDS_FILE, 'utf8')).badWords.map(w => w.toLowerCase());

// Express + Socket.io setup
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 10000;
const PASSWORD = 'CypherDeals';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// simple session storage
const sessions = {};
const warnings = {};

// helper to create folder
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

// --- AUTH MIDDLEWARE ---
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === PASSWORD) {
    res.cookie('auth', crypto.createHash('sha256').update(PASSWORD).digest('hex'), { httpOnly: true });
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

// --- CREATE SESSION ---
app.post('/api/create-session', auth, async (req, res) => {
  const number = req.body.number || 'unknown';
  const sessionId = nanoid(8);
  const sessionPath = path.join(__dirname, 'sessions', sessionId);
  ensureDir(sessionPath);

  // Save info file
  fs.writeFileSync(path.join(sessionPath, 'info.json'), JSON.stringify({ number, created: new Date() }, null, 2));

  try {
    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const sock = makeWASocket({
      auth: state,
      printQRInTerminal: false,
      logger: P({ level: 'silent' }),
      browser: Browsers.macOS('Cypher MDX')
    });

    sessions[sessionId] = sock;
    warnings[sessionId] = {};

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect, qr, pairingCode } = update;
      if (connection === 'close') {
        const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
        if (shouldReconnect) setTimeout(() => startSock(sessionId), 5000);
      } else if (connection === 'open') {
        io.to(sessionId).emit('connected', {});
      }
      if (qr) {
        const qrcode = require('qrcode');
        qrcode.toDataURL(qr, (err, url) => {
          if (!err) io.to(sessionId).emit('qr', { dataUrl: url });
        });
      }
      if (pairingCode) io.to(sessionId).emit('pairing', { code: pairingCode });
      io.to(sessionId).emit('connection', { connection });
    });

    // watch for messages
    sock.ev.on('messages.upsert', async ({ messages }) => {
      const msg = messages[0];
      if (!msg.message || msg.key.fromMe) return;
      const text = msg.message.conversation || msg.message.extendedTextMessage?.text || '';
      const from = msg.key.remoteJid;
      const sender = msg.key.participant || msg.key.remoteJid;

      const containsBadWord = badWords.some((word) => text.toLowerCase().includes(word));
      const containsLink = /(https?:\/\/|www\.)\S+/i.test(text);

      if (containsBadWord || containsLink) {
        const jid = sender;
        warnings[sessionId][jid] = (warnings[sessionId][jid] || 0) + 1;
        const count = warnings[sessionId][jid];
        await sock.sendMessage(from, { text: `⚠️ @${jid.split('@')[0]}, warning ${count}/3: stop sending links or vulgar words!`, mentions: [jid] });
        await delay(500);
        await sock.sendMessage(from, { delete: msg.key });

        if (count >= 3) {
          try {
            await sock.groupParticipantsUpdate(from, [jid], 'remove');
            await sock.sendMessage(from, { text: `🚫 @${jid.split('@')[0]} has been removed after 3 warnings.`, mentions: [jid] });
          } catch (err) {
            console.log('Kick error:', err);
          }
        }
        io.to(sessionId).emit('warnings', warnings[sessionId]);
      }
    });

    res.json({ ok: true, sessionId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Failed to create session' });
  }
});

// --- WARNINGS API ---
app.get('/api/warnings/:sid', auth, (req, res) => {
  const sid = req.params.sid;
  res.json(warnings[sid] || {});
});

// --- SOCKET.IO JOIN ---
io.on('connection', (socket) => {
  socket.on('join-session', (data) => {
    const { sessionId } = data;
    if (sessionId) socket.join(sessionId);
  });
});

ensureDir(path.join(__dirname, 'sessions'));

server.listen(PORT, () => console.log(`⚡ Cypher MDX running on port ${PORT}`));
