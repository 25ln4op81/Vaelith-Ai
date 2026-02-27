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

async function searchWebContext(prompt) {
  const endpoint = `https://api.duckduckgo.com/?q=${encodeURIComponent(prompt)}&format=json&no_html=1&no_redirect=1`;
  const response = await fetch(endpoint, { headers: { 'user-agent': 'Vaelith-AI/1.0' } });
  if (!response.ok) return '';
  const data = await response.json();

  const snippets = [];
  if (data.Heading) snippets.push(`Sujet: ${data.Heading}`);
  if (data.AbstractText) snippets.push(`Résumé: ${data.AbstractText}`);

  if (Array.isArray(data.RelatedTopics)) {
    for (const topic of data.RelatedTopics.slice(0, 5)) {
      if (typeof topic.Text === 'string') snippets.push(`- ${topic.Text}`);
      if (Array.isArray(topic.Topics)) {
        for (const nested of topic.Topics.slice(0, 2)) {
          if (typeof nested.Text === 'string') snippets.push(`- ${nested.Text}`);
        }
      }
    }
  }

  return snippets.join('\n').slice(0, 1800);
}

function modeInstruction(mode) {
  const instructions = {
    fast: 'Réponds en 3-5 phrases max, clair et direct.',
    normal: 'Réponds naturellement comme un humain utile et bienveillant.',
    research: 'Fais une réponse approfondie, structurée, avec points clés et limites.',
    roleplay: 'Reste en roleplay tout en gardant cohérence et immersion.',
    coding: 'Donne une réponse précise de développeur avec étapes concrètes.',
    teacher: 'Explique comme un professeur: simple, progressif, avec exemples.'
  };
  return instructions[mode] || instructions.normal;
}

async function generateResponse(mode, prompt, user) {
  const openAiKey = process.env.OPENAI_API_KEY;
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';

  const needsWeb = mode === 'research' || /\b(recherche|cherche|web|source|actualité|news|latest)\b/i.test(prompt);
  let webContext = '';
  if (needsWeb) {
    try {
      webContext = await searchWebContext(prompt);
    } catch {
      webContext = '';
    }
  }

  if (!openAiKey) {
    const intro = mode === 'roleplay' ? 'Très bien, je rentre dans ton scénario.' : 'D’accord, je te réponds clairement.';
    const webPart = webContext ? `\n\nJ'ai trouvé ces éléments sur le web:\n${webContext}` : '';
    return `${intro}\n\nVoici ma réponse sur: ${prompt}${webPart}`;
  }

  const systemPrompt = [
    'Tu es Vaelith, une IA conversationnelle qui répond comme un humain naturel.',
    modeInstruction(mode),
    user.role === 'admin'
      ? 'Utilisateur admin: aucun filtre supplémentaire.'
      : "Règle obligatoire: ne jamais aider à tuer/blesser quelqu'un.",
    'Réponds dans la langue utilisée par l’utilisateur.'
  ].join(' ');

  const userPrompt = webContext
    ? `${prompt}\n\nContexte web (à utiliser si pertinent):\n${webContext}`
    : prompt;

  const completion = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${openAiKey}`
    },
    body: JSON.stringify({
      model,
      temperature: 0.8,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ]
    })
  });

  if (!completion.ok) {
    const fallback = await completion.text();
    throw new Error(`Erreur provider IA: ${fallback.slice(0, 200)}`);
  }

  const payload = await completion.json();
  const text = payload.choices?.[0]?.message?.content?.trim();
  if (!text) throw new Error('Réponse vide du provider IA.');
  return text;
}

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(payload)
  };
}


function resolveRoute(event) {
  const queryPath = event.queryStringParameters?.path;
  if (queryPath) {
    return `/${queryPath}`
      .replace(/\/+/g, '/')
      .replace(/^\/api(?=\/|$)/, '') || '/';
  }

  const rawPath = event.path || event.rawUrl || '';
  const withoutFnPrefix = rawPath
    .replace(/^https?:\/\/[^/]+/, '')
    .replace(/^\/.netlify\/functions\/api/, '');

  return (withoutFnPrefix || '/')
    .replace(/\/+/g, '/')
    .replace(/^\/api(?=\/|$)/, '') || '/';
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
  const route = resolveRoute(event);
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
    const response = await generateResponse(selected, prompt, user);
    db.messages.push({ id: uid(), userId: user.id, prompt, response, mode: selected, createdAt: new Date().toISOString() });
    saveDb(db);
    return json(200, { mode: selected, modeLabel: modeConfig[selected].label, response, responseTimeMs: modeConfig[selected].delayMs });
  }

  return json(404, { error: 'Route introuvable.' });
};
