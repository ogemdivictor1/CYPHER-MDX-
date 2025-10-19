// pair.js
const {
  makeWASocket,
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  makeCacheableSignalKeyStore
} = require('@whiskeysockets/baileys');

const fs = require('fs');
const path = require('path');
const pino = require('pino');

module.exports = (io, app) => {
  const sessionsDir = path.join(__dirname, 'sessions');
  if (!fs.existsSync(sessionsDir)) fs.mkdirSync(sessionsDir);

  // Store active sessions
  const activeSessions = {};

  // Endpoint: create session (called when user clicks “Generate Pair Code”)
  app.post('/api/create-session', async (req, res) => {
    try {
      const { sessionId } = req.body;
      if (!sessionId) return res.status(400).json({ ok: false, message: 'Missing sessionId' });

      const sessionPath = path.join(sessionsDir, sessionId);
      const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
      const { version } = await fetchLatestBaileysVersion();

      const sock = makeWASocket({
        version,
        logger: pino({ level: 'silent' }),
        printQRInTerminal: false,
        auth: {
          creds: state.creds,
          keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'silent' })),
        },
        browser: ['Cypher MDX', 'Chrome', '1.0.0']
      });

      sock.ev.on('creds.update', saveCreds);

      if (!sock.authState.creds.registered) {
        const phoneNumber = req.body.phoneNumber;
        if (!phoneNumber) return res.json({ ok: false, message: 'Phone number required' });

        // ✅ Generate the pair code
        const code = await sock.requestPairingCode(phoneNumber);
        console.log(`Pair Code for ${phoneNumber}:`, code);
        return res.json({ ok: true, pairCode: code });
      } else {
        return res.json({ ok: true, message: 'Already paired' });
      }

      sock.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'close') {
          const shouldReconnect =
            lastDisconnect.error?.output?.statusCode !== DisconnectReason.loggedOut;
          if (shouldReconnect) createSession(sessionId);
        } else if (connection === 'open') {
          console.log(`✅ WhatsApp connected: ${sessionId}`);
        }
      });

      activeSessions[sessionId] = sock;
    } catch (err) {
      console.error(err);
      res.status(500).json({ ok: false, message: 'Error creating session' });
    }
  });

  // Optional: endpoint to delete session
  app.delete('/api/delete-session/:id', (req, res) => {
    const id = req.params.id;
    const sessionPath = path.join(sessionsDir, id);
    fs.rmSync(sessionPath, { recursive: true, force: true });
    delete activeSessions[id];
    res.json({ ok: true });
  });
};
