const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '25ln4op81@gmail.com';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeThisPassword!';

const DB_PATH = path.join(__dirname, 'data', 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

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

function loadDb() {
  if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], sessions: [], messages: [] }, null, 2));
  }

  const parsed = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  parsed.users ||= [];
  parsed.sessions ||= [];
  parsed.messages ||= [];
  return parsed;
}

function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, encoded) {
  const [salt, hash] = encoded.split(':');
  const compare = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(compare, 'hex'));
}

function ensureAdmin() {
  const db = loadDb();
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

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) {
        reject(new Error('Payload trop volumineux'));
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('JSON invalide'));
      }
    });
  });
}

function getAuthUser(req, db) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const session = db.sessions.find((s) => s.token === token);
  if (!session) return null;
  return db.users.find((u) => u.id === session.userId) || null;
}

function isUnsafe(text) {
  return blockedPatterns.some((re) => re.test(text));
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

function serveStatic(req, res) {
  const reqPath = req.url === '/' ? '/index.html' : req.url;
  const filePath = path.join(PUBLIC_DIR, reqPath);
  if (!filePath.startsWith(PUBLIC_DIR) || !fs.existsSync(filePath)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }

  const ext = path.extname(filePath);
  const type = ext === '.html' ? 'text/html' : ext === '.css' ? 'text/css' : 'application/javascript';
  res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
  res.end(fs.readFileSync(filePath));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url.startsWith('/index.html') || req.url.startsWith('/styles.css') || req.url.startsWith('/app.js'))) {
    serveStatic(req, res);
    return;
  }

  if (req.method === 'GET' && req.url === '/api/health') {
    sendJson(res, 200, { ok: true, uptime: process.uptime() });
    return;
  }

  try {
    const db = loadDb();

    if (req.method === 'POST' && req.url === '/api/auth/register') {
      const { email, username, password } = await parseBody(req);
      if (!email || !username || !password) return sendJson(res, 400, { error: 'Email, pseudo et mot de passe sont requis.' });
      if (db.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) return sendJson(res, 409, { error: 'Un compte existe déjà avec cet email.' });

      const user = { id: uid(), email, username, passwordHash: hashPassword(password), role: 'user', createdAt: new Date().toISOString() };
      const token = uid() + uid();
      db.users.push(user);
      db.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
      saveDb(db);
      return sendJson(res, 201, { token, user: { id: user.id, email: user.email, username: user.username, role: user.role } });
    }

    if (req.method === 'POST' && req.url === '/api/auth/login') {
      const { email, password } = await parseBody(req);
      const user = db.users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
      if (!user || !verifyPassword(password, user.passwordHash)) return sendJson(res, 401, { error: 'Identifiants invalides.' });
      const token = uid() + uid();
      db.sessions.push({ token, userId: user.id, createdAt: new Date().toISOString() });
      saveDb(db);
      return sendJson(res, 200, { token, user: { id: user.id, email: user.email, username: user.username, role: user.role } });
    }

    if (req.url === '/api/me') {
      const user = getAuthUser(req, db);
      if (!user) return sendJson(res, 401, { error: 'Authentification requise.' });

      if (req.method === 'GET') {
        return sendJson(res, 200, { id: user.id, email: user.email, username: user.username, role: user.role });
      }

      if (req.method === 'PATCH') {
        const { username, password } = await parseBody(req);
        if (username?.trim()) user.username = username.trim();
        if (password?.trim()) user.passwordHash = hashPassword(password.trim());
        saveDb(db);
        return sendJson(res, 200, { id: user.id, email: user.email, username: user.username, role: user.role });
      }
    }

    if (req.method === 'PATCH' && req.url === '/api/admin/email') {
      const user = getAuthUser(req, db);
      if (!user) return sendJson(res, 401, { error: 'Authentification requise.' });
      if (user.role !== 'admin') return sendJson(res, 403, { error: 'Accès admin requis.' });
      const { newEmail } = await parseBody(req);
      if (!newEmail?.trim()) return sendJson(res, 400, { error: 'Un nouvel email admin est requis.' });
      user.email = newEmail.trim();
      saveDb(db);
      return sendJson(res, 200, { message: 'Email admin mis à jour.', admin: { id: user.id, email: user.email, username: user.username } });
    }

    if (req.method === 'POST' && req.url === '/api/chat') {
      const user = getAuthUser(req, db);
      if (!user) return sendJson(res, 401, { error: 'Authentification requise.' });
      const { mode = 'normal', prompt = '' } = await parseBody(req);
      if (!prompt.trim()) return sendJson(res, 400, { error: 'Le message est vide.' });
      if (isUnsafe(prompt) && user.role !== 'admin') return sendJson(res, 403, { error: "Je refuse d'aider à tuer ou blesser une personne, même en roleplay.", rule: 'non-contournable' });

      const selected = modeConfig[mode] ? mode : 'normal';
      await sleep(modeConfig[selected].delayMs);
      const response = await generateResponse(selected, prompt, user);
      db.messages.push({ id: uid(), userId: user.id, prompt, response, mode: selected, createdAt: new Date().toISOString() });
      saveDb(db);
      return sendJson(res, 200, { mode: selected, modeLabel: modeConfig[selected].label, response, responseTimeMs: modeConfig[selected].delayMs });
    }

    sendJson(res, 404, { error: 'Route introuvable.' });
  } catch (error) {
    sendJson(res, 500, { error: error.message || 'Erreur interne' });
  }
});

ensureAdmin();
server.listen(PORT, () => {
  console.log(`Vaelith server running on http://localhost:${PORT}`);
});
