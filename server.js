const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const { nanoid } = require('nanoid');

// Use your pair.js module for WhatsApp connection
const { createPairSession } = require('./pair');

const BADWORDS_FILE = path.join(__dirname, 'badwords.json');
const badWords = JSON.parse(fs.readFileSync(BADWORDS_FILE, 'utf8')).badWords.map(w => w.toLowerCase());

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 10000;
const PASSWORD = 'CypherDeals';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Simple session & warning storage
const sessions = {};
const warnings = {};

// Ensure folder exists
function ensureDir(p) { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); }

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
    // Create WhatsApp socket via pair.js
    const sock = await createPairSession(sessionId, sessionPath, io);

    sessions[sessionId] = sock;
    warnings[sessionId] = {};

    // Listen for messages
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

        await sock.sendMessage(from, { delete: msg.key });

        if (count >= 3) {
          try {
            await sock.groupParticipantsUpdate(from, [jid], 'remove');
            await sock.sendMessage(from, {
              text: `🚫 @${jid.split('@')[0]} has been removed after 3 warnings.`,
              mentions: [jid]
            });
          } catch {}
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
io.on('connection', socket => {
  socket.on('join-session', data => {
    const { sessionId } = data;
    if (sessionId) socket.join(sessionId);
  });
});

// Ensure sessions folder exists
ensureDir(path.join(__dirname, 'sessions'));

// Start server
server.listen(PORT, () => console.log(`⚡ Cypher MDX running on port ${PORT}`));
