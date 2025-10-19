const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const P = require('pino');
const { nanoid } = require('nanoid');
const { makeWASocket, useMultiFileAuthState, Browsers, DisconnectReason, delay } = require('@whiskeysockets/baileys');
const qrcode = require('qrcode');

// Load bad words
const BADWORDS_FILE = path.join(__dirname, 'badwords.json');
const badWords = JSON.parse(fs.readFileSync(BADWORDS_FILE, 'utf8')).badWords.map(w => w.toLowerCase());

// Express setup
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 10000;
const PASSWORD = 'CypherDeals';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage
const sessions = {};
const warnings = {};

// Ensure folder exists
function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }

// --- AUTH ---
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

  // Save session info
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

    // --- CONNECTION UPDATE ---
    sock.ev.on('connection.update', async (update) => {
      const { connection, lastDisconnect, qr, pairingCode } = update;

      if (connection === 'close') {
        const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
        if (shouldReconnect) setTimeout(() => createSession(number), 5000);
      }

      if (connection === 'open') {
        io.to(sessionId).emit('connected');
      }

      if (qr) {
        const dataUrl = await qrcode.toDataURL(qr);
        io.to(sessionId).emit('qr', { dataUrl });
      }

      if (pairingCode) {
        io.to(sessionId).emit('pairing', { code: pairingCode });
      }

      io.to(sessionId).emit('connection', { connection });
    });

    // --- MESSAGE HANDLER ---
    sock.ev.on('messages.upsert', async ({ messages }) => {
      const msg = messages[0];
      if (!msg.message || msg.key.fromMe) return;
      const text = msg.message.conversation || msg.message.extendedTextMessage?.text || '';
      const from = msg.key.remoteJid;
      const sender = msg.key.participant || msg.key.remoteJid;

      const hasBadWord = badWords.some(w => text.toLowerCase().includes(w));
      const hasLink = /(https?:\/\/|www\.)\S+/i.test(text);

      if (hasBadWord || hasLink) {
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

// --- SOCKET.IO ---
io.on('connection', (socket) => {
  socket.on('join-session', (data) => {
    const { sessionId } = data;
    if (sessionId) socket.join(sessionId);
  });
});

ensureDir(path.join(__dirname, 'sessions'));

server.listen(PORT, () => console.log(`⚡ Cypher MDX running on port ${PORT}`));
