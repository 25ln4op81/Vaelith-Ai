const state = {
  token: localStorage.getItem('vaelith_token') || null,
  user: null,
  leftPanelHidden: localStorage.getItem('vaelith_left_panel_hidden') === '1'
};

const el = {
  messages: document.querySelector('#messages'),
  authForm: document.querySelector('#auth-form'),
  registerBtn: document.querySelector('#register-btn'),
  profileForm: document.querySelector('#profile-form'),
  modeSelect: document.querySelector('#mode-select'),
  chatForm: document.querySelector('#chat-form'),
  prompt: document.querySelector('#prompt'),
  appShell: document.querySelector('#app-shell'),
  toggleLeftPanelBtn: document.querySelector('#toggle-left-panel'),
  userName: document.querySelector('#user-name'),
  userEmail: document.querySelector('#user-email'),
  userRole: document.querySelector('#user-role'),
  userAvatar: document.querySelector('#user-avatar')
};

function renderUserHeader(user) {
  if (!user) {
    el.userName.textContent = 'Invité';
    el.userEmail.textContent = 'Non connecté';
    el.userRole.textContent = '';
    el.userAvatar.textContent = '?';
    return;
  }

  el.userName.textContent = user.username;
  el.userEmail.textContent = user.email;
  el.userRole.textContent = user.role === 'admin' ? 'Admin' : '';
  el.userAvatar.textContent = user.username?.[0]?.toUpperCase() || 'U';
}

function syncLeftPanelVisibility() {
  el.appShell.classList.toggle('left-hidden', state.leftPanelHidden);
}

function addMessage(content, type = 'ai', options = {}) {
  const msg = document.createElement('article');
  msg.className = `msg ${type}`;
  msg.textContent = content;

  if (type === 'ai' && options.messageId) {
    const actions = document.createElement('div');
    actions.className = 'feedback-actions';

    const up = document.createElement('button');
    up.type = 'button';
    up.className = 'feedback-btn';
    up.textContent = '👍 Utile';

    const down = document.createElement('button');
    down.type = 'button';
    down.className = 'feedback-btn';
    down.textContent = '👎 À améliorer';

    async function sendFeedback(score) {
      try {
        await api('/api/feedback', {
          method: 'POST',
          body: JSON.stringify({ messageId: options.messageId, score })
        });
        actions.innerHTML = '<span class="muted small">Merci pour ton feedback ✅</span>';
      } catch (error) {
        actions.innerHTML = `<span class="muted small">Feedback non envoyé: ${error.message}</span>`;
      }
    }

    up.addEventListener('click', () => sendFeedback(1));
    down.addEventListener('click', () => sendFeedback(-1));

    actions.appendChild(up);
    actions.appendChild(down);
    msg.appendChild(document.createElement('br'));
    msg.appendChild(actions);
  }

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
    throw new Error("Réponse serveur invalide (HTML au lieu de JSON). Ouvre Vaelith depuis l'URL racine du site (pas /public/) et vérifie que /api est bien configuré.");
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
  if (!state.token) {
    state.user = null;
    renderUserHeader(null);
    return;
  }

  try {
    const me = await api('/api/me');
    state.user = me;
    renderUserHeader(me);
  } catch {
    state.token = null;
    state.user = null;
    localStorage.removeItem('vaelith_token');
    renderUserHeader(null);
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
    renderUserHeader(me);
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
    const responseText = `${data.response}\n\n(Mode: ${data.modeLabel} • ${elapsed}s)`;
    addMessage(responseText, 'ai', { messageId: data.messageId });
  } catch (error) {
    addMessage(error.message, 'ai');
  }
});

el.toggleLeftPanelBtn.addEventListener('click', () => {
  state.leftPanelHidden = !state.leftPanelHidden;
  localStorage.setItem('vaelith_left_panel_hidden', state.leftPanelHidden ? '1' : '0');
  syncLeftPanelVisibility();
});

syncLeftPanelVisibility();
refreshMe();
