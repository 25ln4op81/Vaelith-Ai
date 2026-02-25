const state = {
  token: localStorage.getItem('vaelith_token') || null,
  user: null,
  rightPanelHidden: localStorage.getItem('vaelith_right_panel_hidden') === '1'
};

const el = {
  status: document.querySelector('#status'),
  messages: document.querySelector('#messages'),
  authForm: document.querySelector('#auth-form'),
  registerBtn: document.querySelector('#register-btn'),
  profileForm: document.querySelector('#profile-form'),
  modeSelect: document.querySelector('#mode-select'),
  chatForm: document.querySelector('#chat-form'),
  prompt: document.querySelector('#prompt'),
  appShell: document.querySelector('#app-shell'),
  toggleRightPanelBtn: document.querySelector('#toggle-right-panel')
};

function setStatus(message) {
  el.status.textContent = message;
}

function syncRightPanelVisibility() {
  el.appShell.classList.toggle('right-hidden', state.rightPanelHidden);
  el.toggleRightPanelBtn.textContent = state.rightPanelHidden ? 'Afficher panneau' : 'Masquer panneau';
}

function addMessage(content, type = 'ai') {
  const msg = document.createElement('article');
  msg.className = `msg ${type}`;
  msg.textContent = content;
  el.messages.appendChild(msg);
  el.messages.scrollTop = el.messages.scrollHeight;
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;

  const response = await fetch(path, { ...options, headers });
  const contentType = response.headers.get('content-type') || '';
  const rawBody = await response.text();

  if (!contentType.includes('application/json')) {
    throw new Error(
      "Réponse serveur invalide (HTML au lieu de JSON). Ouvre Vaelith depuis l'URL racine du site (pas /public/) et vérifie que /api est bien configuré."
    );
  }

  let payload;
  try {
    payload = rawBody ? JSON.parse(rawBody) : {};
  } catch {
    throw new Error('Réponse JSON invalide renvoyée par le serveur.');
  }

  if (!response.ok) throw new Error(payload.error || 'Erreur API');
  return payload;
}

async function refreshMe() {
  if (!state.token) return;
  try {
    const me = await api('/api/me');
    state.user = me;
    setStatus(`Connecté: ${me.username} (${me.role})`);
  } catch {
    state.token = null;
    localStorage.removeItem('vaelith_token');
    setStatus('Session expirée');
  }
}

el.authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const email = document.querySelector('#email').value;
    const password = document.querySelector('#password').value;
    const payload = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });

    state.token = payload.token;
    localStorage.setItem('vaelith_token', payload.token);
    await refreshMe();
    addMessage('Connexion réussie.', 'ai');
  } catch (error) {
    addMessage(error.message, 'ai');
  }
});

el.registerBtn.addEventListener('click', async () => {
  try {
    const email = document.querySelector('#email').value;
    const username = document.querySelector('#username').value;
    const password = document.querySelector('#password').value;

    const payload = await api('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, username, password })
    });

    state.token = payload.token;
    localStorage.setItem('vaelith_token', payload.token);
    await refreshMe();
    addMessage('Compte créé avec succès.', 'ai');
  } catch (error) {
    addMessage(error.message, 'ai');
  }
});

el.profileForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const username = document.querySelector('#new-username').value;
    const password = document.querySelector('#new-password').value;
    const me = await api('/api/me', {
      method: 'PATCH',
      body: JSON.stringify({ username, password })
    });

    state.user = me;
    setStatus(`Connecté: ${me.username} (${me.role})`);
    addMessage('Profil mis à jour.', 'ai');
  } catch (error) {
    addMessage(error.message, 'ai');
  }
});

el.prompt.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    el.chatForm.requestSubmit();
  }
});

el.chatForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!state.token) {
    addMessage('Connecte-toi avant de discuter.', 'ai');
    return;
  }

  const prompt = el.prompt.value.trim();
  if (!prompt) return;

  addMessage(prompt, 'user');
  el.prompt.value = '';

  try {
    const start = Date.now();
    const data = await api('/api/chat', {
      method: 'POST',
      body: JSON.stringify({ mode: el.modeSelect.value, prompt })
    });

    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    addMessage(`[${data.modeLabel}] ${data.response}\n(temps: ${elapsed}s)`, 'ai');
  } catch (error) {
    addMessage(error.message, 'ai');
  }
});

el.toggleRightPanelBtn.addEventListener('click', () => {
  state.rightPanelHidden = !state.rightPanelHidden;
  localStorage.setItem('vaelith_right_panel_hidden', state.rightPanelHidden ? '1' : '0');
  syncRightPanelVisibility();
});

syncRightPanelVisibility();
refreshMe();
