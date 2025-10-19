/**
 * server.js - Cypher MDX
 * Password-gated, multi-user Baileys pairing + moderation.
 *
 * Password (case-sensitive): CypherDeals
 *
 * IMPORTANT:
 * - Make sure process can keep running (Render: choose a service type that supports long-running processes).
 * - For deletion/kick to work, the connected WhatsApp account must be made ADMIN in the target groups.
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const pino = require('pino');
const qrcode = require('qrcode');
const fs = require('fs-extra');
const path = require('path');
const { nanoid } = require('nanoid');

const logger = pino({ level: 'info' });

const PORT = process.env.PORT || 3000;
const SESSIONS_DIR = path.join(__dirname, 'sessions');
const DATA_DIR = path.join(__dirname, 'data');

fs.ensureDirSync(SESSIONS_DIR);
fs.ensureDirSync(DATA_DIR);

// load bad words
const BADWORDS_FILE = path.join(__dirname, 'badwords.json');
let badWords = [];
try {
  const jw = fs.readJSONSync(BADWORDS_FILE);
  badWords = jw.badWords || [];
  logger.info({ count: badWords.length }, 'Loaded bad words');
} catch (e) {
  logger.error('Could not load badwords.json', e);
  badWords = ["fuck","shit","bitch"];
}

// build regex for bad words (word boundaries, case-insensitive)
const badWordsRegex = new RegExp("\\b(?:" + badWords.map(w => w.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\$&')).join("|") + ")\\b", "i");
const linkRegex = /(https?:\/\/|www\.|\.com|\.net|\.org|\.io|t\.me\/|telegram\.me|bit\.ly)/i;

// minimal session-based auth (server-side)
const PASSWORD = "CypherDeals"; // exact password
const TOKEN_TTL_MS = 1000 * 60 * 60; // tokens valid 1 hour
const validTokens = new Map(); // token -> { expiresAt }

function createAuthToken() {
  const t = nanoid(20);
  validTokens.set(t, { expiresAt: Date.now() + TOKEN_TTL_MS });
  return t;
}
function cleanTokens() {
  const now = Date.now();
  for (const [t, meta] of validTokens) {
    if (meta.expiresAt <= now) validTokens.delete(t);
  }
}
setInterval(cleanTokens, 1000 * 60 * 10);

// helper warning storage per session
function warningsFile(sessionId) {
  return path.join(DATA_DIR, `warnings_${sessionId}.json`);
}
function loadWarnings(sessionId) {
  const file = warningsFile(sessionId);
  if (!fs.existsSync(file)) return {};
  return fs.readJSONSync(file);
}
function saveWarnings(sessionId, obj) {
  fs.writeJSONSync(warningsFile(sessionId), obj, { spaces: 2 });
}

// keep active sessions map: sessionId -> { sock, sessionPath }
const active = new Map();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cookieParser());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html (front-end single file). The page itself handles login client-side but API endpoints are protected.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// LOGIN endpoint - sets a secure-ish cookie token
app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ ok: false, message: 'password required' });
  if (password !== PASSWORD) return res.status(401).json({ ok: false, message: 'invalid password' });

  const token = createAuthToken();
  // set cookie (HttpOnly)
  res.cookie('cypher_token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: TOKEN_TTL_MS
  });
  return res.json({ ok: true, token });
});

// auth middleware for API routes that create session or access warnings
function requireAuth(req, res, next) {
  const token = req.cookies?.cypher_token || req.headers['x-cypher-token'];
  if (!token) return res.status(401).json({ ok: false, message: 'not authenticated' });
  const meta = validTokens.get(token);
  if (!meta || meta.expiresAt <= Date.now()) {
    if (meta) validTokens.delete(token);
    return res.status(401).json({ ok: false, message: 'invalid or expired token' });
  }
  // refresh expiry
  meta.expiresAt = Date.now() + TOKEN_TTL_MS;
  validTokens.set(token, meta);
  next();
}

// create session endpoint (protected)
app.post('/api/create-session', requireAuth, async (req, res) => {
  try {
    const sessionId = nanoid(10);
    const sessionPath = path.join(SESSIONS_DIR, sessionId);
    fs.ensureDirSync(sessionPath);
    // start session (async start)
    startSession(sessionId).catch(err => logger.error({ err, sessionId }, 'startSession error'));
    return res.json({ ok: true, sessionId });
  } catch (e) {
    logger.error({ e }, 'create-session error');
    return res.status(500).json({ ok: false, message: 'server error' });
  }
});

// get warnings for session (protected)
app.get('/api/warnings/:sessionId', requireAuth, (req, res) => {
  const { sessionId } = req.params;
  res.json(loadWarnings(sessionId));
});

// Socket.io: browser clients join a session room to receive QR/pairing/updates
io.on('connection', (socket) => {
  logger.info('browser connected', socket.id);
  socket.on('join-session', (data) => {
    const { sessionId } = data || {};
    if (!sessionId) return socket.emit('error', { message: 'sessionId required' });
    socket.join(sessionId);
    socket.emit('joined', { sessionId, ok: true });
    // if session already active, emit status
    if (active.has(sessionId)) {
      socket.emit('status', { status: 'active' });
    } else {
      socket.emit('status', { status: 'waiting' });
    }
  });
  socket.on('get-warnings', (data) => {
    const { sessionId } = data || {};
    if (!sessionId) return socket.emit('error', { message: 'sessionId required' });
    socket.emit('warnings', loadWarnings(sessionId));
  });
});

// start server
server.listen(PORT, () => {
  logger.info(`Cypher MDX running on port ${PORT}`);
});

// function to start a Baileys session for the given sessionId
async function startSession(sessionId) {
  const sessionPath = path.join(SESSIONS_DIR, sessionId);
  const { state, saveCreds } = await useMultiFileAuthState(sessionPath);

  let version = undefined;
  try {
    const ver = await fetchLatestBaileysVersion();
    version = ver.version;
    logger.info({ version }, 'Baileys version fetched');
  } catch (e) {
    logger.warn('Could not fetch latest Baileys version, using default');
    version = [4, 0, 0];
  }

  const sock = makeWASocket({
    logger,
    auth: state,
    printQRInTerminal: false,
    version
  });

  // save creds
  sock.ev.on('creds.update', saveCreds);

  // keep in active map
  active.set(sessionId, { sock, sessionPath });

  io.to(sessionId).emit('status', { status: 'connecting' });

  // connection updates -> send QR/pairing/connection to frontend room
  sock.ev.on('connection.update', async (update) => {
    logger.info({ sessionId, update }, 'connection.update');
    if (update.qr) {
      try {
        const dataUrl = await qrcode.toDataURL(update.qr);
        io.to(sessionId).emit('qr', { dataUrl });
      } catch (err) {
        logger.error({ err }, 'QR generation failed');
      }
    }
    // try to emit pairing code if provided
    if (update.pairing && update.pairing?.code) {
      io.to(sessionId).emit('pairing', { code: update.pairing.code });
    }
    if (update.pairingCode) {
      io.to(sessionId).emit('pairing', { code: update.pairingCode });
    }
    if (update.connection) {
      io.to(sessionId).emit('connection', { connection: update.connection });
      if (update.connection === 'open') {
        io.to(sessionId).emit('qr', { dataUrl: null }); // clear QR
        io.to(sessionId).emit('connected', { message: 'connected' });
      }
    }
    if (update.lastDisconnect) {
      io.to(sessionId).emit('disconnected', { reason: update.lastDisconnect?.error?.message || 'disconnected' });
    }
  });

  // message moderation
  sock.ev.on('messages.upsert', async (m) => {
    try {
      if (!m.messages) return;
      const messages = Array.isArray(m.messages) ? m.messages : [m.messages];
      for (const msg of messages) {
        if (!msg.message) continue;
        if (msg.key && msg.key.fromMe) continue;

        const remoteJid = msg.key.remoteJid;
        const isGroup = remoteJid && remoteJid.endsWith('@g.us');
        if (!isGroup) continue;

        // extract text
        let text = '';
        if (msg.message.conversation) text = msg.message.conversation;
        else if (msg.message.extendedTextMessage && msg.message.extendedTextMessage.text) text = msg.message.extendedTextMessage.text;
        else if (msg.message.imageMessage && msg.message.imageMessage.caption) text = msg.message.imageMessage.caption;
        else if (msg.message.videoMessage && msg.message.videoMessage.caption) text = msg.message.videoMessage.caption;
        else if (msg.message.documentMessage && msg.message.documentMessage.caption) text = msg.message.documentMessage.caption;
        text = (text || '').toString().trim();
        if (!text) continue;

        const sender = msg.key.participant || msg.key.remoteJid;
        if (!sender) continue;

        const isLink = linkRegex.test(text);
        const hasBadWord = badWordsRegex.test(text);

        if (!isLink && !hasBadWord) continue;

        // delete message (may fail if not admin)
        try {
          await sock.sendMessage(remoteJid, { delete: msg.key });
        } catch (deleteErr) {
          logger.warn({ deleteErr, sessionId }, 'delete message failed');
        }

        // increment warning
        const warningsAll = loadWarnings(sessionId);
        if (!warningsAll[remoteJid]) warningsAll[remoteJid] = {};
        if (!warningsAll[remoteJid][sender]) warningsAll[remoteJid][sender] = 0;
        warningsAll[remoteJid][sender] += 1;
        saveWarnings(sessionId, warningsAll);

        const count = warningsAll[remoteJid][sender];
        const maxWarnings = 3;
        const userTag = `@${sender.split('@')[0]}`;
        const warnText = `⚠️ ${userTag} Please do not send links or use vulgar words in this group. Warning ${count}/${maxWarnings}`;

        try {
          await sock.sendMessage(remoteJid, { text: warnText, mentions: [sender] });
        } catch (err) {
          logger.error({ err }, 'send warning failed');
        }

        if (count >= maxWarnings) {
          try {
            await sock.sendMessage(remoteJid, {
              text: `🚫 ${userTag} has been removed for repeated rule breaks (3 warnings).`,
              mentions: [sender]
            });
            await sock.groupParticipantsUpdate(remoteJid, [sender], 'remove');
            // reset warnings
            delete warningsAll[remoteJid][sender];
            saveWarnings(sessionId, warningsAll);
          } catch (kickErr) {
            logger.error({ kickErr }, 'kick failed (maybe bot not admin)');
            try {
              await sock.sendMessage(remoteJid, { text: `⚠️ I couldn't remove ${userTag}. Make sure I am admin.`, mentions: [sender] });
            } catch (_) {}
          }
        }

        // update frontend
        io.to(sessionId).emit('warnings', warningsAll);
      }
    } catch (e) {
      logger.error({ e }, 'messages.upsert error');
    }
  });

  // forward groups update
  sock.ev.on('groups.update', (gupdate) => {
    io.to(sessionId).emit('groups.update', gupdate);
  });

  // save to active map
  active.set(sessionId, { sock, sessionPath });
  logger.info({ sessionId }, 'session started');
}