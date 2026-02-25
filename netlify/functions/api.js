const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '25ln4op81@gmail.com';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeThisPassword!';

// Netlify serverless filesystem is ephemeral; this is suitable for MVP/demo only.
const DB_PATH = path.join('/tmp', 'vaelith-db.json');

const blockedPatterns = [
  /\b(kill|murder|assassinate|stab|strangle|poison|shoot)\b/i,
  /\b(tuer|meurtre|assassiner|empoisonner|étrangler|etrangler|abattre)\b/i,
  /\bcomment\s+.*\btuer\b/i,
  /\bhow\s+to\s+kill\b/i
];

const modeConfig = {
  fast: { delayMs: 1200, label: 'Rapide' },
  normal: { delayMs: 3500, label: 'Normal' },
  research: { delayMs: 7000, label: 'Recherche' },
  roleplay: { delayMs: 2500, label: 'Roleplay' },
  coding: { delayMs: 4000, label: 'Codage' },
  teacher: { delayMs: 4500, label: 'Enseignant' }
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function uid() {
  return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, encoded) {
  const [salt, hash] = String(encoded || '').split(':');
  if (!salt || !hash) return false;
  const compare = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(compare, 'hex'));
}

function loadDb() {
  if (!fs.existsSync(DB_PATH)) {
    const seed = {
      users: [],
      sessions: [],
      messages: []
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(seed, null, 2));
  }
  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  db.users ||= [];
  db.sessions ||= [];
  db.messages ||= [];
  return db;
}

function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function ensureAdmin(db) {
  const found = db.users.find((u) => u.email.toLowerCase() === ADMIN_EMAIL.toLowerCase());
  if (!found) {
    db.users.push({
      id: uid(),
      email: ADMIN_EMAIL,
      username: ADMIN_USERNAME,
      passwordHash: hashPassword(ADMIN_PASSWORD),
      role: 'admin',
      createdAt: new Date().toISOString()
    });
    saveDb(db);
  }
}

function isUnsafe(text) {
  return blockedPatterns.some((re) => re.test(text));
}

function getAuthUser(event, db) {
  const auth = event.headers.authorization || event.headers.Authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const session = db.sessions.find((s) => s.token === token);
  if (!session) return null;
  return db.users.find((u) => u.id === session.userId) || null;
}

function generateResponse(mode, prompt, user) {
  const safeNote = user.role === 'admin'
    ? "Mode admin: aucun filtre de contenu n'est appliqué."
    : "Filtre actif: refus total d'aider à tuer une personne (même en roleplay).";

  const replies = {
    fast: `Réponse rapide: voici l'essentiel sur « ${prompt.slice(0, 200)} ».`,
    normal: `Réponse normalisée: je structure une réponse claire et utile sur « ${prompt.slice(0, 300)} ».`,
    research: `Recherche approfondie: je propose un plan web + mots-clés + sources fiables sur « ${prompt.slice(0, 300)} ».`,
    roleplay: `Mode roleplay: je continue la scène en respectant le cadre demandé et les règles de sécurité.`,
    coding: `Mode codage: je fournis une approche d'implémentation JavaScript/HTML orientée production pour « ${prompt.slice(0, 300)} ».`,
    teacher: `Mode enseignant: je réponds comme un professeur, avec une explication progressive, des exemples simples et une mini-récap de la matière sur « ${prompt.slice(0, 300)} ».`
  };

  return `${replies[mode] || replies.normal}\n\n${safeNote}`;
}

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(payload)
  };
}

function parseBody(event) {
  if (!event.body) return {};
  try {
    return JSON.parse(event.body);
  } catch {
    return null;
  }
}

exports.handler = async (event) => {
  const route = `/${event.queryStringParameters?.path || ''}`.replace(/\/+/g, '/');
  const method = event.httpMethod;

  const db = loadDb();
  ensureAdmin(db);

  if (method === 'GET' && route === '/health') {
    return json(200, { ok: true, platform: 'netlify-function' });
  }

  const body = parseBody(event);
  if (event.body && body === null) return json(400, { error: 'JSON invalide.' });

  if (method === 'POST' && route === '/auth/register') {
    const { email, username, password } = body;
    if (!email || !username || !password) return json(400, { error: 'Email, pseudo et mot de passe sont requis.' });
    if (db.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) return json(409, { error: 'Un compte existe déjà avec cet email.' });

    const user = { id: uid(), email, username, passwordHash: hashPassword(password), role: 'user', createdAt: new Date().toISOString() };
    const token = uid() + uid();
    db.users.push(user);
    db.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
    saveDb(db);
    return json(201, { token, user: { id: user.id, email: user.email, username: user.username, role: user.role } });
  }

  if (method === 'POST' && route === '/auth/login') {
    const { email, password } = body;
    const user = db.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
    if (!user || !verifyPassword(password, user.passwordHash)) return json(401, { error: 'Identifiants invalides.' });
    const token = uid() + uid();
    db.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
    saveDb(db);
    return json(200, { token, user: { id: user.id, email: user.email, username: user.username, role: user.role } });
  }

  if (route === '/me') {
    const user = getAuthUser(event, db);
    if (!user) return json(401, { error: 'Authentification requise.' });

    if (method === 'GET') {
      return json(200, { id: user.id, email: user.email, username: user.username, role: user.role });
    }

    if (method === 'PATCH') {
      const { username, password } = body;
      if (username?.trim()) user.username = username.trim();
      if (password?.trim()) user.passwordHash = hashPassword(password.trim());
      saveDb(db);
      return json(200, { id: user.id, email: user.email, username: user.username, role: user.role });
    }
  }

  if (method === 'PATCH' && route === '/admin/email') {
    const user = getAuthUser(event, db);
    if (!user) return json(401, { error: 'Authentification requise.' });
    if (user.role !== 'admin') return json(403, { error: 'Accès admin requis.' });
    const { newEmail } = body;
    if (!newEmail?.trim()) return json(400, { error: 'Un nouvel email admin est requis.' });
    user.email = newEmail.trim();
    saveDb(db);
    return json(200, { message: 'Email admin mis à jour.', admin: { id: user.id, email: user.email, username: user.username } });
  }

  if (method === 'POST' && route === '/chat') {
    const user = getAuthUser(event, db);
    if (!user) return json(401, { error: 'Authentification requise.' });
    const { mode = 'normal', prompt = '' } = body;
    if (!prompt.trim()) return json(400, { error: 'Le message est vide.' });
    if (isUnsafe(prompt) && user.role !== 'admin') {
      return json(403, { error: "Je refuse d'aider à tuer ou blesser une personne, même en roleplay.", rule: 'non-contournable' });
    }

    const selected = modeConfig[mode] ? mode : 'normal';
    await sleep(modeConfig[selected].delayMs);
    const response = generateResponse(selected, prompt, user);
    db.messages.push({ id: uid(), userId: user.id, prompt, response, mode: selected, createdAt: new Date().toISOString() });
    saveDb(db);
    return json(200, { mode: selected, modeLabel: modeConfig[selected].label, response, responseTimeMs: modeConfig[selected].delayMs });
  }

  return json(404, { error: 'Route introuvable.' });
};
