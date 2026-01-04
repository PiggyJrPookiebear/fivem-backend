(function () {
  const TOKEN_KEY = 'spermlings_auth_token';
  const USER_KEY = 'spermlings_auth_user';

  function apiBase() {
    return (localStorage.getItem('spermlings_api_base') || 'http://localhost:3001').replace(/\/$/, '');
  }

  function getToken() {
    return (localStorage.getItem(TOKEN_KEY) || '').trim();
  }

  function setSession(token, user) {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  function currentUser() {
    try {
      const raw = localStorage.getItem(USER_KEY);
      if (!raw) return null;
      const user = JSON.parse(raw);
      if (!user || typeof user.username !== 'string') return null;
      return user;
    } catch {
      return null;
    }
  }

  function isLoggedIn() {
    return !!getToken();
  }

  async function postJson(url, body, extra) {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(extra && extra.headers ? extra.headers : {}),
      },
      body: JSON.stringify(body || {}),
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (!res.ok) {
      const msg = json && json.error ? `${json.error}` : `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.body = json;
      throw err;
    }
    return json;
  }

  async function getJson(url, extra) {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        ...(extra && extra.headers ? extra.headers : {}),
      },
      cache: 'no-store',
    });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (!res.ok) {
      const msg = json && json.error ? `${json.error}` : `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.body = json;
      throw err;
    }
    return json;
  }

  async function signup(username, password) {
    const json = await postJson(`${apiBase()}/api/auth/signup`, { username, password });
    if (json && json.token) {
      setSession(json.token, json.user);
      return true;
    }
    return false;
  }

  async function login(username, password) {
    const json = await postJson(`${apiBase()}/api/auth/login`, { username, password });
    if (json && json.token) {
      setSession(json.token, json.user);
      return true;
    }
    return false;
  }

  function logout() {
    clearSession();
    window.location.href = 'login.html';
  }

  function requireAuth() {
    if (!isLoggedIn()) {
      const here = window.location.pathname.split('/').pop() || 'index.html';
      window.location.href = `login.html?next=${encodeURIComponent(here)}`;
    }
  }

  function isOwner() {
    const user = currentUser();
    return !!user && (user.role === 'owner');
  }

  function isAdmin() {
    const user = currentUser();
    if (!user) return false;
    return user.role === 'owner' || user.role === 'admin';
  }

  function requireOwner() {
    requireAuth();
    if (!isOwner()) {
      window.location.href = 'index.html';
    }
  }

  function requireAdmin() {
    requireAuth();
    if (!isAdmin()) {
      window.location.href = 'index.html';
    }
  }

  async function me() {
    const token = getToken();
    if (!token) return null;
    try {
      const json = await getJson(`${apiBase()}/api/auth/me`, {
        headers: { authorization: `Bearer ${token}` },
      });
      if (json && json.user) {
        setSession(token, json.user);
        return json.user;
      }
      return null;
    } catch {
      clearSession();
      return null;
    }
  }

  if (getToken() && !currentUser()) {
    me().catch(() => undefined);
  }

  window.SPERMLINGS_AUTH = {
    apiBase,
    currentUser,
    getToken,
    isLoggedIn,
    isAdmin,
    isOwner,
    login,
    signup,
    logout,
    me,
    requireAuth,
    requireAdmin,
    requireOwner,
  };
})();
