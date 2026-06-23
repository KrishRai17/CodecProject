const statusMessage = document.getElementById('statusMessage');
const authView = document.getElementById('authView');
const vaultView = document.getElementById('vaultView');
const authForm = document.getElementById('authForm');
const noteForm = document.getElementById('noteForm');
const notesList = document.getElementById('notesList');
const userLabel = document.getElementById('userLabel');

const setStatus = (message, tone = 'info') => {
  statusMessage.textContent = message;
  statusMessage.className = `status ${tone}`;
};

const showVault = (user) => {
  authView.classList.add('hidden');
  vaultView.classList.remove('hidden');
  userLabel.textContent = `Signed in as ${user.name} (${user.email})`;
  loadNotes();
};

const showAuth = () => {
  vaultView.classList.add('hidden');
  authView.classList.remove('hidden');
  userLabel.textContent = '';
};

const getToken = () => localStorage.getItem('vaultToken');

const api = async (path, options = {}) => {
  const response = await fetch(path, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(options.auth ? { Authorization: `Bearer ${getToken()}` } : {}),
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || 'Request failed');
  }

  return data;
};

const saveToken = (data) => {
  if (data.token) localStorage.setItem('vaultToken', data.token);
  if (data.user) localStorage.setItem('vaultUser', JSON.stringify(data.user));
};

const loadNotes = async () => {
  try {
    const data = await api('/api/notes', { auth: true });
    notesList.innerHTML = '';

    if (!data.notes || data.notes.length === 0) {
      notesList.innerHTML = '<li class="empty-state">No notes yet. Create your first encrypted note.</li>';
      return;
    }

    data.notes.forEach((note) => {
      const item = document.createElement('li');
      item.className = 'note-card';
      item.innerHTML = `
        <div>
          <strong>${escapeHtml(note.title)}</strong>
          <p>${escapeHtml(note.content)}</p>
        </div>
        <button type="button" class="ghost delete-btn" data-id="${note.id}">Delete</button>
      `;
      notesList.appendChild(item);
    });
  } catch (error) {
    setStatus(error.message, 'error');
  }
};

const escapeHtml = (value) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#39;');

authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = document.getElementById('name').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  try {
    const data = await api('/api/auth/register', {
      method: 'POST',
      body: { name, email, password },
    });
    saveToken(data);
    setStatus('Registration successful. You can now create notes.', 'success');
    showVault(data.user);
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

const loginBtn = document.getElementById('loginBtn');
loginBtn.addEventListener('click', async () => {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  try {
    const data = await api('/api/auth/login', {
      method: 'POST',
      body: { email, password },
    });
    saveToken(data);
    setStatus('Login successful.', 'success');
    showVault(data.user);
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

noteForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  try {
    await api('/api/notes', {
      method: 'POST',
      auth: true,
      body: {
        title: document.getElementById('noteTitle').value.trim(),
        content: document.getElementById('noteContent').value.trim(),
      },
    });
    noteForm.reset();
    setStatus('Note saved securely.', 'success');
    loadNotes();
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

notesList.addEventListener('click', async (event) => {
  const button = event.target.closest('.delete-btn');
  if (!button) return;

  try {
    await api(`/api/notes/${button.dataset.id}`, { method: 'DELETE', auth: true });
    setStatus('Note deleted.', 'success');
    loadNotes();
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

const logoutBtn = document.getElementById('logoutBtn');
logoutBtn.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } catch (error) {
    // Ignore logout failures and clear local storage.
  }

  localStorage.removeItem('vaultToken');
  localStorage.removeItem('vaultUser');
  showAuth();
  setStatus('Signed out successfully.', 'success');
});

const savedUser = JSON.parse(localStorage.getItem('vaultUser') || 'null');
if (savedUser && getToken()) {
  showVault(savedUser);
}
