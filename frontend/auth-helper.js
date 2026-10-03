// Tambahkan ke frontend index.html.
// Ini adalah helper autentikasi. Untuk tahap awal, gunakan halaman/login
// sebelum user masuk ke dashboard.

async function authAPI(path, options = {}) {
  const response = await fetch(`/api/auth${path}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });

  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; }
  catch (_) { data = {}; }

  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }

  return data;
}

async function getCurrentUser() {
  try {
    const result = await authAPI('/me');
    return result.user;
  } catch (_) {
    return null;
  }
}

async function login(username, password) {
  return authAPI('/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });
}

async function logout() {
  await authAPI('/logout', { method: 'POST' });
  window.location.href = '/login.html';
}
