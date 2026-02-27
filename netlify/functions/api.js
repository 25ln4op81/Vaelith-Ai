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
  db.feedback ||= [];
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

function getRecentContext(db, userId, limit = 6) {
  return db.messages
    .filter((m) => m.userId === userId)
    .slice(-limit)
    .map((m) => ({ id: m.id, prompt: m.prompt, response: m.response, mode: m.mode }));
}

function getAdaptiveSignals(db, userId) {
  const userFeedback = db.feedback.filter((f) => f.userId === userId);
  const likedIds = new Set(userFeedback.filter((f) => f.score > 0).map((f) => f.messageId));
  const dislikedIds = new Set(userFeedback.filter((f) => f.score < 0).map((f) => f.messageId));

  const likedMessages = db.messages.filter((m) => likedIds.has(m.id));
  const dislikedMessages = db.messages.filter((m) => dislikedIds.has(m.id));

  const likedKeywords = likedMessages.flatMap((m) => extractKeywords(m.prompt, 4));
  const dislikedKeywords = dislikedMessages.flatMap((m) => extractKeywords(m.prompt, 4));

  return {
    totalFeedback: userFeedback.length,
    positiveCount: likedMessages.length,
    negativeCount: dislikedMessages.length,
    likedKeywords: [...new Set(likedKeywords)].slice(0, 8),
    dislikedKeywords: [...new Set(dislikedKeywords)].slice(0, 8)
  };
}

function tokenize(text) {
  return String(text || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(Boolean);
}

function scoreIntents(prompt, mode) {
  const tokens = tokenize(prompt);
  const score = { explanation: 0, action: 0, compare: 0, creative: 0, technical: 0 };

  for (const t of tokens) {
    if (['pourquoi', 'comment', 'explique', 'explain', 'why', 'how'].includes(t)) score.explanation += 2;
    if (['fais', 'genere', 'build', 'create', 'code', 'script', 'etapes'].includes(t)) score.action += 2;
    if (['vs', 'comparaison', 'difference', 'better', 'meilleur'].includes(t)) score.compare += 2;
    if (['histoire', 'roleplay', 'scene', 'imagine', 'fiction'].includes(t)) score.creative += 2;
    if (['api', 'bug', 'backend', 'frontend', 'netlify', 'database', 'kubernetes'].includes(t)) score.technical += 2;
  }

  if (mode === 'coding') score.technical += 3;
  if (mode === 'teacher') score.explanation += 3;
  if (mode === 'roleplay') score.creative += 3;
  if (mode === 'research') score.compare += 1;

  return score;
}

function extractKeywords(prompt, max = 8) {
  const stop = new Set(['le', 'la', 'les', 'de', 'des', 'du', 'un', 'une', 'et', 'ou', 'a', 'à', 'the', 'and', 'or', 'to', 'for', 'in', 'on']);
  const freq = new Map();
  for (const tok of tokenize(prompt)) {
    if (tok.length < 3 || stop.has(tok)) continue;
    freq.set(tok, (freq.get(tok) || 0) + 1);
  }
  return [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, max).map(([k]) => k);
}

function chooseVariant(prompt, mode, variants) {
  const seed = crypto.createHash('sha1').update(`${mode}:${prompt}`).digest()[0];
  return variants[seed % variants.length];
}

function buildReasoningPlan({ prompt, mode, history, webContext, adaptiveSignals }) {
  const intents = scoreIntents(prompt, mode);
  const keywords = extractKeywords(prompt);
  const topIntent = Object.entries(intents).sort((a, b) => b[1] - a[1])[0][0];

  return {
    intents,
    topIntent,
    keywords,
    hasWeb: Boolean(webContext),
    lastUserTopic: history.length ? history[history.length - 1].prompt.slice(0, 120) : null,
    style: modeInstruction(mode),
    adaptiveSignals
  };
}

function renderResponse({ prompt, mode, user, plan, webContext }) {
  const openings = {
    fast: ['Voici l’essentiel tout de suite :', 'Réponse directe :', 'Je vais à l’essentiel :'],
    normal: ['Bonne question.', 'Je vois ce que tu veux.', 'Très bien, on y va.'],
    research: ['J’ai fait une analyse croisée.', 'J’ai structuré une réponse de recherche.', 'Je t’ai préparé une synthèse approfondie.'],
    roleplay: ['Très bien, j’entre dans le rôle.', 'Parfait, continuons la scène.', 'Je reprends le roleplay.'],
    coding: ['OK, approche développeur :', 'Très bien, plan technique :', 'Voici une implémentation pragmatique :'],
    teacher: ['Super question, on va le faire pas à pas.', 'Parfait, je te l’explique simplement.', 'Très bien, cours express :']
  };

  const opening = chooseVariant(prompt, mode, openings[mode] || openings.normal);
  const bullets = [];

  if (plan.keywords.length) bullets.push(`Points clés détectés : ${plan.keywords.join(', ')}.`);
  if (plan.topIntent === 'technical') bullets.push('Je priorise une réponse structurée avec étapes actionnables.');
  if (plan.topIntent === 'explanation') bullets.push('Je vais vulgariser puis approfondir progressivement.');
  if (plan.topIntent === 'creative') bullets.push('Je garde une narration fluide et cohérente.');
  if (plan.topIntent === 'compare') bullets.push('Je compare les options avec avantages/inconvénients.');
  if (plan.topIntent === 'action') bullets.push('Je fournis un plan concret que tu peux appliquer immédiatement.');
  if (plan.lastUserTopic) bullets.push(`Contexte récent pris en compte : « ${plan.lastUserTopic} ».`);
  if (plan.hasWeb) bullets.push('J’ai enrichi la réponse avec des signaux web utiles.');

  if (plan.adaptiveSignals?.totalFeedback) {
    bullets.push(`J'ai appris de ${plan.adaptiveSignals.totalFeedback} feedback(s) utilisateur récents.`);
  }
  if (plan.adaptiveSignals?.likedKeywords?.length) {
    bullets.push(`Préférences détectées: ${plan.adaptiveSignals.likedKeywords.join(', ')}.`);
  }

  let answer = `${opening}

${bullets.map((b) => `- ${b}`).join('\n')}`;
  answer += `\n\nRéponse : ${prompt}`;
  if (webContext) answer += `\n\nContexte web (résumé):\n${webContext}`;
  if (mode === 'teacher') answer += '\n\nMini-récap: retiens surtout la logique, puis applique-la sur un exemple.';
  if (mode === 'coding') answer += '\n\nSi tu veux, je peux générer ensuite une version prête à copier-coller.';
  if (user.role === 'admin') answer += '\n\n[Mode admin activé]';
  return answer;
}

async function generateResponse({ mode, prompt, user, history, adaptiveSignals }) {
  const needsWeb = mode === 'research' || /\b(recherche|cherche|web|source|actualite|actualité|news|latest)\b/i.test(prompt);
  let webContext = '';
  if (needsWeb) {
    try {
      webContext = await searchWebContext(prompt);
    } catch {
      webContext = '';
    }
  }

  const plan = buildReasoningPlan({ prompt, mode, history, webContext, adaptiveSignals });
  return renderResponse({ prompt, mode, user, plan, webContext });
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
    const history = getRecentContext(db, user.id, 6);
    const adaptiveSignals = getAdaptiveSignals(db, user.id);
    const response = await generateResponse({ mode: selected, prompt, user, history, adaptiveSignals });
    const messageId = uid();
    db.messages.push({ id: messageId, userId: user.id, prompt, response, mode: selected, createdAt: new Date().toISOString() });
    saveDb(db);
    return json(200, { mode: selected, modeLabel: modeConfig[selected].label, response, responseTimeMs: modeConfig[selected].delayMs, messageId });
  }


  if (method === 'POST' && route === '/feedback') {
    const user = getAuthUser(event, db);
    if (!user) return json(401, { error: 'Authentification requise.' });
    const { messageId, score = 0, note = '' } = body;
    if (!messageId) return json(400, { error: 'messageId requis.' });
    const numericScore = Number(score);
    if (![1, -1].includes(numericScore)) return json(400, { error: 'score doit être 1 ou -1.' });

    const message = db.messages.find((m) => m.id === messageId && m.userId === user.id);
    if (!message) return json(404, { error: 'Message introuvable pour ce compte.' });

    db.feedback.push({ id: uid(), userId: user.id, messageId, score: numericScore, note: String(note).slice(0, 500), createdAt: new Date().toISOString() });
    saveDb(db);
    return json(201, { ok: true });
  }

  return json(404, { error: 'Route introuvable.' });
};
