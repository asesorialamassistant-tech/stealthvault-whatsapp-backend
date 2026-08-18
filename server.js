import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import QRCode from 'qrcode';
import multer from 'multer';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import mime from 'mime-types';
import NodeCache from 'node-cache';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const baileys = require('@whiskeysockets/baileys');
const makeWASocket = baileys.default || baileys;
const {
  useMultiFileAuthState,
  DisconnectReason,
  downloadMediaMessage,
  proto,
} = baileys;
import pino from 'pino';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const AUTH_DIR = join(__dirname, 'auth_info');
const SECRET_TOKEN = process.env.SECRET_TOKEN || 'stealthvault_secret_2024';

// ─── Logger (silent in production to avoid leaking data) ─────────────────────
const logger = pino({ level: 'silent' });

// ─── Custom In-Memory Store (Zero-Dependency) ───────────────────────────────
const store = {
  chats: {
    all: () => Object.values(store.chats.data),
    data: {}
  },
  messages: {},
  rawMessages: {},
  bind: (ev) => {
    ev.on('messaging-history.set', ({ chats, contacts, messages }) => {
      if (chats) {
        for (const chat of chats) {
          store.chats.data[chat.id] = { ...store.chats.data[chat.id], ...chat };
        }
      }
      if (contacts) {
        for (const contact of contacts) {
          const id = contact.id;
          const name = contact.name || contact.notify || contact.verifiedName;
          store.chats.data[id] = { ...store.chats.data[id], id, name };
        }
      }
      if (messages) {
        for (const msg of messages) {
          const jid = msg.key?.remoteJid;
          if (jid) {
            if (!store.messages[jid]) store.messages[jid] = [];
            if (!store.rawMessages[jid]) store.rawMessages[jid] = {};
            if (msg.key?.id) store.rawMessages[jid][msg.key.id] = msg;
            const parsed = parseMessage(msg);
            if (parsed && !store.messages[jid].some(m => m.id === parsed.id)) {
              store.messages[jid].push(parsed);
            }
          }
        }
      }
    });
    ev.on('chats.set', ({ chats }) => {
      for (const chat of chats) {
        store.chats.data[chat.id] = { ...store.chats.data[chat.id], ...chat };
      }
    });
    ev.on('chats.upsert', (chats) => {
      for (const chat of chats) {
        store.chats.data[chat.id] = { ...store.chats.data[chat.id], ...chat };
      }
    });
    ev.on('chats.update', (updates) => {
      for (const update of updates) {
        if (store.chats.data[update.id]) {
          store.chats.data[update.id] = { ...store.chats.data[update.id], ...update };
        }
      }
    });
    ev.on('contacts.set', ({ contacts }) => {
      for (const contact of contacts) {
        const id = contact.id;
        const name = contact.name || contact.notify || contact.verifiedName;
        store.chats.data[id] = { ...store.chats.data[id], id, name };
      }
    });
    ev.on('contacts.update', (updates) => {
      for (const update of updates) {
        const id = update.id;
        if (store.chats.data[id]) {
          const name = update.name || update.notify || store.chats.data[id].name;
          store.chats.data[id].name = name;
        }
      }
    });
    ev.on('messages.upsert', ({ messages }) => {
      for (const msg of messages) {
        const jid = msg.key?.remoteJid;
        if (jid) {
          if (!store.chats.data[jid]) {
            store.chats.data[jid] = { id: jid, name: msg.pushName || jid.split('@')[0], unreadCount: 0 };
          }
          store.chats.data[jid].conversationTimestamp = msg.messageTimestamp;
          if (!store.messages[jid]) store.messages[jid] = [];
          if (!store.rawMessages[jid]) store.rawMessages[jid] = {};
          if (msg.key?.id) store.rawMessages[jid][msg.key.id] = msg;
          const parsed = parseMessage(msg);
          if (parsed && !store.messages[jid].some(m => m.id === parsed.id)) {
            store.messages[jid].push(parsed);
          }
          broadcast('new_message', { chatId: jid, message: parsed });
        }
      }
    });
  }
};

// ─── Message cache for quick access ──────────────────────────────────────────
const msgCache = new NodeCache({ stdTTL: 3600, checkperiod: 120 });

// ─── State ────────────────────────────────────────────────────────────────────
let sock = null;
let currentQR = null;
let connectionStatus = 'disconnected'; // disconnected | connecting | qr_ready | connected
const wsClients = new Set();

// ─── Express + HTTP server ────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 64 * 1024 * 1024 } });
const httpServer = createServer(app);

// ─── WebSocket server ─────────────────────────────────────────────────────────
const wss = new WebSocketServer({ server: httpServer });

function broadcast(event, data) {
  const payload = JSON.stringify({ event, data, ts: Date.now() });
  for (const client of wsClients) {
    if (client.readyState === 1) client.send(payload);
  }
}

wss.on('connection', (ws, req) => {
  // Simple token auth via query param
  const url = new URL(req.url, `http://localhost`);
  if (url.searchParams.get('token') !== SECRET_TOKEN) {
    ws.close(4001, 'Unauthorized');
    return;
  }
  wsClients.add(ws);
  // Send current state on connect
  ws.send(JSON.stringify({ event: 'status', data: { status: connectionStatus }, ts: Date.now() }));
  if (currentQR && connectionStatus === 'qr_ready') {
    ws.send(JSON.stringify({ event: 'qr', data: { qr: currentQR }, ts: Date.now() }));
  }
  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireToken(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (token !== SECRET_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ─── WhatsApp connection ──────────────────────────────────────────────────────
async function connectToWhatsApp() {
  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);

  sock = makeWASocket({
    auth: state,
    logger,
    printQRInTerminal: false,
    browser: baileys.Browsers ? baileys.Browsers.ubuntu('Desktop') : ['Ubuntu', 'Chrome', '110.0.5563.64'],
    syncFullHistory: true,
    markOnlineOnConnect: true,
    keepAliveIntervalMs: 15_000,
    maxMsgRetryCount: 5,
    defaultQueryTimeoutMs: 60_000,
    generateHighQualityLinkPreview: false,
  });

  store.bind(sock.ev);

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      // Generate QR as base64 PNG image
      currentQR = await QRCode.toDataURL(qr, { errorCorrectionLevel: 'M', width: 300, margin: 2 });
      connectionStatus = 'qr_ready';
      broadcast('qr', { qr: currentQR });
      broadcast('status', { status: connectionStatus });
    }

    if (connection === 'open') {
      currentQR = null;
      connectionStatus = 'connected';
      broadcast('status', { status: 'connected' });
      console.log('✅ WhatsApp connected');
    }

    if (connection === 'close') {
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const isLoggedOut = statusCode === DisconnectReason.loggedOut || statusCode === 401 || statusCode === 403;
      connectionStatus = isLoggedOut ? 'disconnected' : 'connecting';
      broadcast('status', { status: connectionStatus });
      if (isLoggedOut) {
        console.log('🚪 Session logged out / invalid. Wiping auth dir for new QR...');
        try {
          const { rmSync } = await import('fs');
          if (existsSync(AUTH_DIR)) {
            rmSync(AUTH_DIR, { recursive: true, force: true });
          }
        } catch (e) {
          console.error('Error removing auth dir:', e);
        }
        setTimeout(connectToWhatsApp, 2000);
      } else {
        console.log('🔄 Reconnecting...');
        setTimeout(connectToWhatsApp, 3000);
      }
    }
  });

  sock.ev.on('messages.update', (updates) => {
    for (const update of updates) {
      broadcast('message_update', update);
    }
  });
}

function parseMessage(msg) {
  let content = msg.message;
  if (!content) return null;

  // Baileys extractMessageContent / recursive unwrapping
  if (baileys.extractMessageContent) {
    content = baileys.extractMessageContent(content) || content;
  }

  while (content?.ephemeralMessage || content?.viewOnceMessage || content?.viewOnceMessageV2 || content?.documentWithCaptionMessage) {
    content = content?.ephemeralMessage?.message || content?.viewOnceMessage?.message || content?.viewOnceMessageV2?.message || content?.documentWithCaptionMessage?.message;
  }
  if (!content) return null;

  const key = msg.key;
  const fromMe = Boolean(key.fromMe);
  const chatId = key.remoteJid;
  const msgId = key.id;
  const timestamp = (msg.messageTimestamp?.toNumber?.() ?? msg.messageTimestamp) * 1000 || Date.now();
  const pushName = msg.pushName || '';

  let type = 'unknown';
  let text = '';
  let mediaType = null;
  let fileName = null;
  let mimeType = null;

  if (typeof content.conversation === 'string') {
    type = 'text';
    text = content.conversation;
  } else if (content.extendedTextMessage) {
    type = 'text';
    text = content.extendedTextMessage.text || '';
  } else if (content.imageMessage) {
    type = 'media';
    mediaType = 'image';
    mimeType = content.imageMessage.mimetype || 'image/jpeg';
    text = content.imageMessage.caption || '';
  } else if (content.videoMessage) {
    type = 'media';
    mediaType = 'video';
    mimeType = content.videoMessage.mimetype || 'video/mp4';
    text = content.videoMessage.caption || '';
  } else if (content.audioMessage) {
    type = 'media';
    mediaType = 'audio';
    mimeType = content.audioMessage.mimetype || 'audio/ogg';
  } else if (content.documentMessage) {
    type = 'media';
    mediaType = 'document';
    mimeType = content.documentMessage.mimetype || 'application/octet-stream';
    fileName = content.documentMessage.fileName || 'document';
    text = content.documentMessage.caption || '';
  } else if (content.stickerMessage) {
    type = 'sticker';
    mediaType = 'image';
    mimeType = 'image/webp';
  } else if (content.reactionMessage) {
    type = 'reaction';
    text = content.reactionMessage.text || '';
  } else {
    // Traverse object values for any text or media content
    for (const val of Object.values(content)) {
      if (!val || typeof val !== 'object') continue;
      if (typeof val.text === 'string' && val.text.length > 0) {
        type = 'text';
        text = val.text;
        break;
      }
      if (typeof val.caption === 'string' && val.caption.length > 0) {
        type = 'media';
        text = val.caption;
        mediaType = val.mimetype?.startsWith('video') ? 'video' : 'image';
        mimeType = val.mimetype || 'image/jpeg';
        break;
      }
      if (val.conversation) {
        type = 'text';
        text = val.conversation;
        break;
      }
    }
  }

  return {
    id: msgId,
    chatId,
    fromMe,
    pushName,
    type,
    text,
    mediaType,
    mimeType,
    fileName,
    timestamp,
    hasMedia: type === 'media' || type === 'sticker',
    _raw: null, // don't expose raw
  };
}

// ─── REST API routes ──────────────────────────────────────────────────────────

// Health check (public)
app.get('/health', (req, res) => res.json({ ok: true, version: '1.6.0-keepalive-live', status: connectionStatus }));

// Connection status
app.get('/api/status', requireToken, (req, res) => {
  res.json({ status: connectionStatus });
});

// Get current QR as base64 PNG
app.get('/api/qr', requireToken, (req, res) => {
  if (connectionStatus === 'connected') {
    return res.json({ status: 'connected', qr: null });
  }
  if (!currentQR) {
    return res.json({ status: connectionStatus, qr: null });
  }
  res.json({ status: 'qr_ready', qr: currentQR });
});

// Get all chats
app.get('/api/chats', requireToken, async (req, res) => {
  try {
    if (!sock || connectionStatus !== 'connected') {
      return res.status(503).json({ error: 'Not connected to WhatsApp' });
    }
    const chats = store.chats.all();
    const result = chats
      .filter(c => c.id && !c.id.includes('@lid'))
      .slice(0, 100)
      .map(c => ({
        id: c.id,
        name: c.name || c.id.split('@')[0],
        unreadCount: c.unreadCount || 0,
        isGroup: c.id.endsWith('@g.us'),
        lastMessageTime: c.conversationTimestamp
          ? (c.conversationTimestamp?.toNumber?.() ?? c.conversationTimestamp) * 1000
          : null,
      }));
    res.json({ chats: result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get messages for a chat
app.get('/api/messages/:chatId', requireToken, async (req, res) => {
  try {
    if (!sock || connectionStatus !== 'connected') {
      return res.status(503).json({ error: 'Not connected' });
    }
    const chatId = decodeURIComponent(req.params.chatId);
    const limit = parseInt(req.query.limit || '200');
    const msgs = store.messages[chatId] || [];
    // Sort ascending by timestamp so latest messages are at the bottom
    const sorted = [...msgs].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    res.json({ messages: sorted.slice(-limit) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Send text message
app.post('/api/send/text', requireToken, async (req, res) => {
  try {
    if (!sock || connectionStatus !== 'connected') {
      return res.status(503).json({ error: 'Not connected' });
    }
    const { chatId, text } = req.body;
    if (!chatId || !text) return res.status(400).json({ error: 'chatId and text required' });
    const result = await sock.sendMessage(chatId, { text });
    res.json({ ok: true, messageId: result?.key?.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Send media (image, video, audio, document)
app.post('/api/send/media', requireToken, upload.single('file'), async (req, res) => {
  try {
    if (!sock || connectionStatus !== 'connected') {
      return res.status(503).json({ error: 'Not connected' });
    }
    const { chatId, caption, mediaType } = req.body;
    if (!chatId || !req.file) return res.status(400).json({ error: 'chatId and file required' });

    const fileBuffer = req.file.buffer;
    const detectedMime = req.file.mimetype || mime.lookup(req.file.originalname) || 'application/octet-stream';
    const filename = req.file.originalname || 'file';

    let msgContent;
    if (mediaType === 'image' || detectedMime.startsWith('image/')) {
      msgContent = { image: fileBuffer, caption: caption || '', mimetype: detectedMime };
    } else if (mediaType === 'video' || detectedMime.startsWith('video/')) {
      msgContent = { video: fileBuffer, caption: caption || '', mimetype: detectedMime };
    } else if (mediaType === 'audio' || detectedMime.startsWith('audio/')) {
      msgContent = { audio: fileBuffer, mimetype: detectedMime, ptt: false };
    } else {
      msgContent = { document: fileBuffer, fileName: filename, mimetype: detectedMime, caption: caption || '' };
    }

    const result = await sock.sendMessage(chatId, msgContent);
    res.json({ ok: true, messageId: result?.key?.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Download media for a specific message
app.get('/api/media/:chatId/:messageId', requireToken, async (req, res) => {
  try {
    if (!sock || connectionStatus !== 'connected') {
      return res.status(503).json({ error: 'Not connected' });
    }
    const chatId = decodeURIComponent(req.params.chatId);
    const messageId = req.params.messageId;
    let target = store.rawMessages[chatId]?.[messageId];
    if (!target && sock.loadMessages) {
      const messages = await sock.loadMessages(chatId, 50, undefined);
      target = messages.find(m => m.key.id === messageId);
    }
    if (!target) return res.status(404).json({ error: 'Message not found' });

    const buffer = await downloadMediaMessage(target, 'buffer', {}, { reuploadRequest: sock.updateMediaMessage });
    const mimeType = target.message?.imageMessage?.mimetype
      || target.message?.videoMessage?.mimetype
      || target.message?.audioMessage?.mimetype
      || target.message?.documentMessage?.mimetype
      || 'application/octet-stream';

    res.set('Content-Type', mimeType);
    res.set('Content-Length', buffer.length);
    res.send(buffer);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Request 8-digit pairing code for phone number
app.post('/api/pairing-code', requireToken, async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    if (!phoneNumber) return res.status(400).json({ error: 'Número de teléfono es requerido' });
    const cleanNumber = phoneNumber.replace(/[^0-9]/g, '');
    if (!sock) {
      await connectToWhatsApp();
    }
    const code = await sock.requestPairingCode(cleanNumber);
    res.json({ ok: true, pairingCode: code });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Reset session and force new QR code
app.post('/api/reset', requireToken, async (req, res) => {
  try {
    if (sock) {
      try { sock.ev.removeAllListeners(); sock.end(undefined); } catch (e) {}
      sock = null;
    }
    const { rmSync } = await import('fs');
    if (existsSync(AUTH_DIR)) {
      rmSync(AUTH_DIR, { recursive: true, force: true });
    }
    currentQR = null;
    connectionStatus = 'connecting';
    broadcast('status', { status: 'connecting' });
    connectToWhatsApp().catch(console.error);
    res.json({ ok: true, message: 'Session reset successfully' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Logout / disconnect
app.post('/api/logout', requireToken, async (req, res) => {
  try {
    if (sock) {
      try { await sock.logout(); } catch (e) {}
      sock = null;
    }
    const { rmSync } = await import('fs');
    if (existsSync(AUTH_DIR)) {
      rmSync(AUTH_DIR, { recursive: true, force: true });
    }
    connectionStatus = 'disconnected';
    broadcast('status', { status: 'disconnected' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  console.log(`🚀 StealthVault backend running on port ${PORT}`);
  connectToWhatsApp().catch(console.error);
});
