import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Client, Events, GatewayIntentBits, Partials } from 'discord.js';

dotenv.config();

const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const GUILD_ID = process.env.GUILD_ID;
const ANNOUNCEMENTS_CHANNEL_ID = process.env.ANNOUNCEMENTS_CHANNEL_ID;
const STAFF_ROLE_ID = process.env.STAFF_ROLE_ID;

const OWNER_ROLE_ID = process.env.OWNER_ROLE_ID;
const COOWNER_ROLE_ID = process.env.COOWNER_ROLE_ID;
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;
const DEVELOPER_ROLE_ID = process.env.DEVELOPER_ROLE_ID;
const MOD_ROLE_ID = process.env.MOD_ROLE_ID;
const TRIAL_MOD_ROLE_ID = process.env.TRIAL_MOD_ROLE_ID;

const TICKETS_CHANNEL_ID = process.env.TICKETS_CHANNEL_ID;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const AUTH_SECRET = process.env.AUTH_SECRET;

const PORT = Number(process.env.PORT || 3001);
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const ANNOUNCEMENTS_LIMIT = Number(process.env.ANNOUNCEMENTS_LIMIT || 25);

if (!GUILD_ID) {
  console.error('Missing GUILD_ID in env');
  process.exit(1);
}

const dataDir = path.resolve(process.cwd());
const announcementsFile = path.join(dataDir, 'announcements.json');
const ticketsFile = path.join(dataDir, 'tickets.json');
const usersFile = path.join(dataDir, 'users.json');

async function readAnnouncements() {
  try {
    const raw = await fs.readFile(announcementsFile, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeAnnouncements(items) {
  const trimmed = items.slice(0, ANNOUNCEMENTS_LIMIT);
  await fs.writeFile(announcementsFile, JSON.stringify(trimmed, null, 2), 'utf8');
  return trimmed;
}

async function readTickets() {
  try {
    const raw = await fs.readFile(ticketsFile, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeTickets(items) {
  await fs.writeFile(ticketsFile, JSON.stringify(items, null, 2), 'utf8');
  return items;
}

async function readUsers() {
  try {
    const raw = await fs.readFile(usersFile, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeUsers(items) {
  await fs.writeFile(usersFile, JSON.stringify(items, null, 2), 'utf8');
  return items;
}

let announcementsCache = await readAnnouncements();

let ticketsCache = await readTickets();

let usersCache = await readUsers();

if (AUTH_SECRET) {
  const ownerUsername = 'Dr Piggy jr';
  const ownerPassword = '@Pmcord3010@';
  const existingOwnerIndex = usersCache.findIndex(
    (u) => u && typeof u.username === 'string' && u.username.toLowerCase() === ownerUsername.toLowerCase(),
  );
  if (existingOwnerIndex === -1) {
    const userId = crypto.randomBytes(12).toString('hex');
    const passwordHash = await hashPassword(ownerPassword);
    const user = { id: userId, username: ownerUsername, passwordHash, role: 'owner', createdAt: Date.now() };
    usersCache = [user, ...usersCache];
    writeUsers(usersCache).catch(() => undefined);
  } else {
    const existing = usersCache[existingOwnerIndex];
    const passwordHash = await hashPassword(ownerPassword);
    usersCache[existingOwnerIndex] = Object.assign({}, existing, {
      username: ownerUsername,
      passwordHash,
      role: 'owner',
    });
    writeUsers(usersCache).catch(() => undefined);
  }
}

let staffCache = null;

function pushAnnouncement(item) {
  announcementsCache = [item, ...announcementsCache].slice(0, ANNOUNCEMENTS_LIMIT);
  writeAnnouncements(announcementsCache).catch(() => undefined);
}

const app = express();
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));
app.use(express.json());

function base64UrlEncode(buf) {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(str) {
  const padded = `${str}`.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  return Buffer.from(padded + pad, 'base64');
}

function signToken(payload) {
  if (!AUTH_SECRET) return null;
  const body = base64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest();
  return `${body}.${base64UrlEncode(sig)}`;
}

function verifyToken(token) {
  if (!AUTH_SECRET) return null;
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest();
  const got = base64UrlDecode(sig);
  if (got.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(got, expected)) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(body).toString('utf8'));
    if (!payload || typeof payload !== 'object') return null;
    if (typeof payload.userId !== 'string' || typeof payload.username !== 'string') return null;
    if (payload.role != null && typeof payload.role !== 'string') return null;
    if (typeof payload.exp !== 'number' || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function getAuthToken(req) {
  const raw = req.header('authorization') || '';
  const m = raw.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : '';
}

function requireAuth(req, res) {
  if (!AUTH_SECRET) {
    res.status(500).json({ error: 'Auth not configured (missing AUTH_SECRET)' });
    return null;
  }
  const token = getAuthToken(req);
  const payload = verifyToken(token);
  if (!payload) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }
  return payload;
}

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(password, salt);
  return `${base64UrlEncode(salt)}.${base64UrlEncode(key)}`;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const parts = stored.split('.');
  if (parts.length !== 2) return false;
  const salt = base64UrlDecode(parts[0]);
  const expected = base64UrlDecode(parts[1]);
  const got = await scryptAsync(password, salt);
  if (got.length !== expected.length) return false;
  return crypto.timingSafeEqual(got, expected);
}

function requireAdminApiKey(req, res) {
  if (!ADMIN_API_KEY) return true;
  const key = req.header('x-admin-key');
  if (key && key === ADMIN_API_KEY) return true;
  res.status(401).json({ error: 'unauthorized' });
  return false;
}

app.post('/api/auth/signup', async (req, res) => {
  if (!AUTH_SECRET) {
    res.status(500).json({ error: 'Auth not configured (missing AUTH_SECRET)' });
    return;
  }

  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (!username || !password) {
    res.status(400).json({ error: 'Missing fields (username, password)' });
    return;
  }

  if (username.length > 32 || password.length > 200) {
    res.status(400).json({ error: 'Invalid input' });
    return;
  }

  const existing = usersCache.find((u) => u && typeof u.username === 'string' && u.username.toLowerCase() === username.toLowerCase());
  if (existing) {
    res.status(409).json({ error: 'username_taken' });
    return;
  }

  const userId = crypto.randomBytes(12).toString('hex');
  const passwordHash = await hashPassword(password);
  const user = { id: userId, username, passwordHash, role: 'user', createdAt: Date.now() };

  usersCache = [user, ...usersCache];
  writeUsers(usersCache).catch(() => undefined);

  const exp = Date.now() + 1000 * 60 * 60 * 24 * 14;
  const token = signToken({ userId, username, role: user.role, exp });
  res.json({ ok: true, token, user: { id: userId, username, role: user.role } });
});

app.post('/api/auth/login', async (req, res) => {
  if (!AUTH_SECRET) {
    res.status(500).json({ error: 'Auth not configured (missing AUTH_SECRET)' });
    return;
  }

  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (!username || !password) {
    res.status(400).json({ error: 'Missing fields (username, password)' });
    return;
  }

  const user = usersCache.find((u) => u && typeof u.username === 'string' && u.username.toLowerCase() === username.toLowerCase());
  if (!user) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const exp = Date.now() + 1000 * 60 * 60 * 24 * 14;
  const role = typeof user.role === 'string' ? user.role : 'user';
  const token = signToken({ userId: user.id, username: user.username, role, exp });
  res.json({ ok: true, token, user: { id: user.id, username: user.username, role } });
});

app.get('/api/auth/me', async (req, res) => {
  const auth = requireAuth(req, res);
  if (!auth) return;
  const user = usersCache.find((u) => u && u.id === auth.userId);
  const role = user && typeof user.role === 'string' ? user.role : (typeof auth.role === 'string' ? auth.role : 'user');
  res.json({ ok: true, user: { id: auth.userId, username: auth.username, role } });
});

app.get('/api/my/tickets', async (req, res) => {
  const auth = requireAuth(req, res);
  if (!auth) return;

  const items = ticketsCache
    .filter((t) => t && t.ownerUserId === auth.userId)
    .slice()
    .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
    .map((t) => ({
      id: t.id,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
      status: t.status,
      subject: t.subject,
    }));

  res.json({ ok: true, tickets: items });
});

app.get('/api/my/tickets/:id', async (req, res) => {
  const auth = requireAuth(req, res);
  if (!auth) return;

  const id = req.params.id;
  const ticket = ticketsCache.find((t) => t && t.id === id);
  if (!ticket) {
    res.status(404).json({ error: 'not_found' });
    return;
  }
  if (ticket.ownerUserId !== auth.userId) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  res.json({ ok: true, ticket });
});

app.post('/api/my/tickets/:id/message', async (req, res) => {
  const auth = requireAuth(req, res);
  if (!auth) return;

  const id = req.params.id;
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!message) {
    res.status(400).json({ error: 'Missing field (message)' });
    return;
  }
  if (message.length > 1600) {
    res.status(400).json({ error: 'Message too long' });
    return;
  }

  const idx = ticketsCache.findIndex((t) => t && t.id === id);
  if (idx === -1) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  const ticket = ticketsCache[idx];
  if (ticket.ownerUserId !== auth.userId) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  if (ticket.status === 'closed') {
    res.status(403).json({ error: 'ticket_closed' });
    return;
  }

  const now = Date.now();
  ticket.messages = Array.isArray(ticket.messages) ? ticket.messages : [];
  ticket.messages.push({ at: now, from: 'user', text: message });
  ticket.updatedAt = now;
  ticketsCache[idx] = ticket;
  writeTickets(ticketsCache).catch(() => undefined);

  try {
    if (TICKETS_CHANNEL_ID) {
      const channel = await client.channels.fetch(TICKETS_CHANNEL_ID);
      if (channel && 'send' in channel) {
        const lines = [
          '📩 Ticket Message',
          `ID: ${ticket.id}`,
          `User: ${auth.username}`,
          `Subject: ${ticket.subject || ''}`,
          '',
          message,
        ];
        await channel.send({ content: lines.join('\n') });
      }
    }
  } catch {
    // ignore
  }

  res.json({ ok: true });
});

let discordReady = false;
let lastMemberCount = null;

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
  ],
  partials: [Partials.Channel, Partials.Message],
});

app.post('/api/tickets', async (req, res) => {
  const auth = requireAuth(req, res);
  if (!auth) return;

  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
  const contact = typeof req.body?.contact === 'string' ? req.body.contact.trim() : '';
  const subject = typeof req.body?.subject === 'string' ? req.body.subject.trim() : '';
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';

  if (!name || !email || !subject || !message) {
    res.status(400).json({ error: 'Missing fields (name, email, subject, message)' });
    return;
  }

  if (message.length > 1600 || subject.length > 120 || name.length > 80 || email.length > 160 || contact.length > 120) {
    res.status(400).json({ error: 'One or more fields too long' });
    return;
  }

  const ticketId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const now = Date.now();

  const ticket = {
    id: ticketId,
    createdAt: now,
    updatedAt: now,
    status: 'open',
    ownerUserId: auth.userId,
    ownerUsername: auth.username,
    name,
    email,
    contact,
    subject,
    messages: [
      { at: now, from: 'user', text: message },
    ],
  };

  ticketsCache = [ticket, ...ticketsCache];
  writeTickets(ticketsCache).catch(() => undefined);

  res.json({ ok: true, ticketId });

  (async () => {
    if (!TICKETS_CHANNEL_ID) return;
    if (!discordReady) return;
    const timeoutMs = 4000;

    const withTimeout = async (p) => {
      const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs));
      return await Promise.race([p, timeout]);
    };

    try {
      const channel = await withTimeout(client.channels.fetch(TICKETS_CHANNEL_ID));
      if (!channel || !('send' in channel)) return;

      const lines = [
        '🆕 New Ticket',
        `ID: ${ticketId}`,
        `User: ${auth.username}`,
        `Name: ${name}`,
        `Email: ${email || 'n/a'}`,
        `Contact: ${contact || 'n/a'}`,
        `Subject: ${subject}`,
        '',
        message,
      ];

      await withTimeout(channel.send({ content: lines.join('\n') }));
    } catch {
      // ignore
    }
  })().catch(() => undefined);
});

app.post('/api/tickets/check', async (req, res) => {
  const id = typeof req.body?.ticketId === 'string' ? req.body.ticketId.trim() : '';
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
  const contact = typeof req.body?.contact === 'string' ? req.body.contact.trim() : '';

  if (!id || !name || !email) {
    res.status(400).json({ error: 'Missing fields (ticketId, name, email)' });
    return;
  }

  const ticket = ticketsCache.find((t) => t && t.id === id);
  if (!ticket) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  const storedName = typeof ticket.name === 'string' ? ticket.name : '';
  const storedEmail = typeof ticket.email === 'string' ? ticket.email : '';
  const storedContact = typeof ticket.contact === 'string' ? ticket.contact : '';

  const norm = (s) => (s || '').trim().toLowerCase();
  const emailOk = norm(email) === norm(storedEmail);
  const contactOk = contact ? norm(contact) === norm(storedContact) : true;
  const nameOk = storedName ? norm(name) === norm(storedName) : true;

  if (!emailOk || !contactOk || !nameOk) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  res.json({
    ok: true,
    ticket: {
      id: ticket.id,
      createdAt: ticket.createdAt,
      updatedAt: ticket.updatedAt,
      status: ticket.status,
      name: ticket.name,
      email: ticket.email,
      contact: ticket.contact,
      subject: ticket.subject,
      messages: Array.isArray(ticket.messages) ? ticket.messages : [],
    },
  });
});

app.post('/api/tickets/message', async (req, res) => {
  const id = typeof req.body?.ticketId === 'string' ? req.body.ticketId.trim() : '';
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
  const contact = typeof req.body?.contact === 'string' ? req.body.contact.trim() : '';
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';

  if (!id || !name || !email || !message) {
    res.status(400).json({ error: 'Missing fields (ticketId, name, email, message)' });
    return;
  }

  if (message.length > 1600) {
    res.status(400).json({ error: 'Message too long' });
    return;
  }

  const idx = ticketsCache.findIndex((t) => t && t.id === id);
  if (idx === -1) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  const ticket = ticketsCache[idx];
  const storedName = typeof ticket.name === 'string' ? ticket.name : '';
  const storedEmail = typeof ticket.email === 'string' ? ticket.email : '';
  const storedContact = typeof ticket.contact === 'string' ? ticket.contact : '';

  const norm = (s) => (s || '').trim().toLowerCase();
  const emailOk = norm(email) === norm(storedEmail);
  const contactOk = contact ? norm(contact) === norm(storedContact) : true;
  const nameOk = storedName ? norm(name) === norm(storedName) : true;

  if (!emailOk || !contactOk || !nameOk) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const now = Date.now();
  ticket.messages = Array.isArray(ticket.messages) ? ticket.messages : [];
  ticket.messages.push({ at: now, from: 'user', text: message });
  ticket.updatedAt = now;
  ticketsCache[idx] = ticket;
  writeTickets(ticketsCache).catch(() => undefined);

  try {
    if (TICKETS_CHANNEL_ID) {
      const channel = await client.channels.fetch(TICKETS_CHANNEL_ID);
      if (channel && 'send' in channel) {
        const lines = [
          '📩 Ticket Message',
          `ID: ${ticket.id}`,
          `From: ${ticket.name}${ticket.email ? ` (${ticket.email})` : ''}`,
          `Subject: ${ticket.subject || ''}`,
          '',
          message,
        ];
        await channel.send({ content: lines.join('\n') });
      }
    }
  } catch {
    // ignore
  }

  res.json({ ok: true });
});

app.get('/api/admin/tickets', async (req, res) => {
  if (!requireAdminApiKey(req, res)) return;
  const items = ticketsCache
    .slice()
    .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
    .map((t) => ({
      id: t.id,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
      status: t.status,
      ownerUserId: t.ownerUserId,
      ownerUsername: t.ownerUsername,
      name: t.name,
      email: t.email,
      contact: t.contact,
      subject: t.subject,
    }));
  res.json({ ok: true, tickets: items });
});

app.get('/api/admin/tickets/:id', async (req, res) => {
  if (!requireAdminApiKey(req, res)) return;
  const id = req.params.id;
  const ticket = ticketsCache.find((t) => t.id === id);
  if (!ticket) {
    res.status(404).json({ error: 'not_found' });
    return;
  }
  res.json({ ok: true, ticket });
});

app.post('/api/admin/tickets/:id/reply', async (req, res) => {
  if (!requireAdminApiKey(req, res)) return;
  const id = req.params.id;
  const text = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!text) {
    res.status(400).json({ error: 'Missing field (message)' });
    return;
  }
  if (text.length > 1600) {
    res.status(400).json({ error: 'Message too long' });
    return;
  }

  const idx = ticketsCache.findIndex((t) => t.id === id);
  if (idx === -1) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  const ticket = ticketsCache[idx];
  const now = Date.now();
  ticket.messages = Array.isArray(ticket.messages) ? ticket.messages : [];
  ticket.messages.push({ at: now, from: 'admin', text });
  ticket.updatedAt = now;
  ticketsCache[idx] = ticket;
  writeTickets(ticketsCache).catch(() => undefined);

  try {
    if (TICKETS_CHANNEL_ID) {
      const channel = await client.channels.fetch(TICKETS_CHANNEL_ID);
      if (channel && 'send' in channel) {
        const lines = [
          '💬 Ticket Reply',
          `ID: ${ticket.id}`,
          `To: ${ticket.name}${ticket.contact ? ` (${ticket.contact})` : ''}`,
          '',
          text,
        ];
        await channel.send({ content: lines.join('\n') });
      }
    }
  } catch {
    // ignore
  }

  res.json({ ok: true });
});

app.post('/api/admin/tickets/:id/status', async (req, res) => {
  if (!requireAdminApiKey(req, res)) return;
  const id = req.params.id;
  const status = typeof req.body?.status === 'string' ? req.body.status.trim() : '';

  const allowed = new Set(['open', 'in_progress', 'closed']);
  if (!allowed.has(status)) {
    res.status(400).json({ error: 'Invalid status' });
    return;
  }

  const idx = ticketsCache.findIndex((t) => t && t.id === id);
  if (idx === -1) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  const ticket = ticketsCache[idx];
  const now = Date.now();
  ticket.status = status;
  ticket.updatedAt = now;
  ticketsCache[idx] = ticket;
  writeTickets(ticketsCache).catch(() => undefined);

  try {
    if (TICKETS_CHANNEL_ID) {
      const channel = await client.channels.fetch(TICKETS_CHANNEL_ID);
      if (channel && 'send' in channel) {
        await channel.send({ content: `🔧 Ticket Status Updated\nID: ${ticket.id}\nStatus: ${ticket.status}` });
      }
    }
  } catch {
    // ignore
  }

  res.json({ ok: true });
});

app.post('/api/admin/tickets/:id/close', async (req, res) => {
  if (!requireAdminApiKey(req, res)) return;
  const id = req.params.id;
  const idx = ticketsCache.findIndex((t) => t.id === id);
  if (idx === -1) {
    res.status(404).json({ error: 'not_found' });
    return;
  }

  const ticket = ticketsCache[idx];
  const now = Date.now();
  ticket.status = 'closed';
  ticket.updatedAt = now;
  ticketsCache[idx] = ticket;
  writeTickets(ticketsCache).catch(() => undefined);

  try {
    if (TICKETS_CHANNEL_ID) {
      const channel = await client.channels.fetch(TICKETS_CHANNEL_ID);
      if (channel && 'send' in channel) {
        await channel.send({ content: `✅ Ticket Closed\nID: ${ticket.id}` });
      }
    }
  } catch {
    // ignore
  }

  res.json({ ok: true });
});

client.once(Events.ClientReady, async () => {
  discordReady = true;
  console.log(`Discord bot logged in as ${client.user?.tag}`);

  try {
    const guild = await client.guilds.fetch(GUILD_ID);
    lastMemberCount = guild.memberCount ?? null;
  } catch {
    // ignore
  }
});

client.on('messageCreate', async (message) => {
  if (!ANNOUNCEMENTS_CHANNEL_ID) return;
  if (!message.guild || message.guild.id !== GUILD_ID) return;
  if (message.channelId !== ANNOUNCEMENTS_CHANNEL_ID) return;
  if (message.author?.bot) return;

  const item = {
    id: message.id,
    content: message.content || '',
    author: {
      id: message.author.id,
      username: message.author.username,
      displayName: message.member?.displayName || message.author.username,
      avatarUrl: message.author.displayAvatarURL?.({ size: 128 }) || null,
    },
    createdAt: message.createdTimestamp,
    url: message.url,
  };

  pushAnnouncement(item);
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, discordReady });
});

app.get('/api/discord/member-count', async (_req, res) => {
  try {
    const guild = await client.guilds.fetch(GUILD_ID);
    lastMemberCount = guild.memberCount ?? lastMemberCount;
    res.json({ guildId: GUILD_ID, count: lastMemberCount });
  } catch (e) {
    res.status(503).json({ guildId: GUILD_ID, count: lastMemberCount, error: 'unavailable' });
  }
});

app.get('/api/discord/announcements', async (_req, res) => {
  res.json({ guildId: GUILD_ID, items: announcementsCache });
});

app.get('/api/discord/staff', async (_req, res) => {
  const rankRoleIds = [
    OWNER_ROLE_ID,
    COOWNER_ROLE_ID,
    ADMIN_ROLE_ID,
    DEVELOPER_ROLE_ID,
    MOD_ROLE_ID,
    TRIAL_MOD_ROLE_ID,
  ].filter(Boolean);

  if (!rankRoleIds.length) {
    res.status(400).json({ error: 'No rank role IDs configured' });
    return;
  }

  try {
    const guild = await client.guilds.fetch(GUILD_ID);
    const members = await guild.members.fetch();

    const toUser = (m) => ({
      id: m.user.id,
      username: m.user.username,
      displayName: m.displayName,
      avatarUrl: m.user.displayAvatarURL({ size: 128 }),
    });

    const roleSet = new Set(rankRoleIds);
    const eligible = members.filter((m) => {
      for (const id of roleSet) {
        if (m.roles.cache.has(id)) return true;
      }
      return false;
    });

    const groups = [
      { key: 'owner', label: 'Owner', roleId: OWNER_ROLE_ID },
      { key: 'co_owner', label: 'Co-Owner', roleId: COOWNER_ROLE_ID },
      { key: 'admin', label: 'Admin', roleId: ADMIN_ROLE_ID },
      { key: 'developer', label: 'Developer', roleId: DEVELOPER_ROLE_ID },
      { key: 'moderator', label: 'Moderator', roleId: MOD_ROLE_ID },
      { key: 'trial_moderator', label: 'Trial Moderator', roleId: TRIAL_MOD_ROLE_ID },
    ].filter((g) => !!g.roleId);

    const used = new Set();
    const grouped = groups.map((g) => {
      const users = eligible
        .filter((m) => !used.has(m.user.id) && m.roles.cache.has(g.roleId))
        .map((m) => {
          used.add(m.user.id);
          return toUser(m);
        })
        .sort((a, b) => a.displayName.localeCompare(b.displayName));

      return { key: g.key, label: g.label, roleId: g.roleId, members: users };
    });

    const payload = { guildId: GUILD_ID, groups: grouped, stale: false };
    staffCache = payload;
    res.json(payload);
  } catch {
    if (staffCache) {
      res.json({ ...staffCache, stale: true });
      return;
    }
    res.status(503).json({ error: 'unavailable' });
  }
});

async function start() {
  if (!DISCORD_TOKEN) {
    console.error('Missing DISCORD_TOKEN in env');
    process.exit(1);
  }

  await client.login(DISCORD_TOKEN);

  app.listen(PORT, () => {
    console.log(`API listening on http://localhost:${PORT}`);
  });
}

start().catch((e) => {
  console.error(e);
  process.exit(1);
});
