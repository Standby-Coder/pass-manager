const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8080';
const TOKEN_KEY = 'auth_token';
const OFFLINE_CACHE_KEY = 'offline_entries';
const OFFLINE_USER_KEY = 'offline_user';

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function saveToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function request(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  const token = getToken();

  if (token && !headers.Authorization) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers
  });

  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json() : null;

  if (!response.ok) {
    const message = data?.error || data?.message || 'Request failed';
    throw new Error(message);
  }

  return data;
}

export async function registerUser(payload) {
  return request('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export async function loginUser(payload) {
  return request('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export async function verifyMFA(mfaToken, code) {
  return request('/api/auth/mfa/verify', {
    method: 'POST',
    body: JSON.stringify({ mfa_token: mfaToken, code })
  });
}

export async function enableMFA() {
  return request('/api/auth/mfa/enable', { method: 'POST' });
}

export async function confirmEnableMFA(code) {
  return request('/api/auth/mfa/enable/verify', {
    method: 'POST',
    body: JSON.stringify({ code })
  });
}

export async function disableMFA(password) {
  return request('/api/auth/mfa/disable', {
    method: 'POST',
    body: JSON.stringify({ password })
  });
}

export async function fetchPasswords(search = '', category = '') {
  const params = new URLSearchParams();
  if (search) params.set('search', search);
  if (category) params.set('category', category);
  const qs = params.toString();
  const data = await request(`/api/passwords${qs ? '?' + qs : ''}`);

  // Cache the latest entries for offline access
  try {
    const entries = data?.entries || [];
    const cached = entries.slice(-10); // last 10 entries
    localStorage.setItem(OFFLINE_CACHE_KEY, JSON.stringify(cached));
  } catch { /* ignore storage errors */ }

  return data;
}

export async function createPasswordEntry(payload) {
  return request('/api/passwords', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export async function updatePasswordEntry(id, payload) {
  return request(`/api/passwords/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  });
}

export async function deletePasswordEntry(id) {
  return request(`/api/passwords/${id}`, {
    method: 'DELETE'
  });
}

export async function requestPasswordReset(email) {
  return request('/api/auth/password-reset/request', {
    method: 'POST',
    body: JSON.stringify({ email })
  });
}

export async function confirmPasswordReset(token, newPassword) {
  return request('/api/auth/password-reset/confirm', {
    method: 'POST',
    body: JSON.stringify({ token, new_password: newPassword })
  });
}

export async function fetchSecurityPolicy() {
  return request('/api/auth/security-policy');
}

export async function generatePassword(length) {
  return request('/api/auth/generate-password', {
    method: 'POST',
    body: JSON.stringify({ length: length || 0 })
  });
}

// Sync API
export async function syncVault(lastSyncAt, entries) {
  return request('/api/sync', {
    method: 'POST',
    body: JSON.stringify({ last_sync_at: lastSyncAt, entries })
  });
}

// Export/Import API
export async function exportVault(password) {
  return request('/api/vault/export', {
    method: 'POST',
    body: JSON.stringify({ password })
  });
}

export async function importVault(password, data) {
  return request('/api/vault/import', {
    method: 'POST',
    body: JSON.stringify({ password, data })
  });
}

// Admin API
export async function getAdminSettings() {
  return request('/api/admin/settings');
}

export async function updateAdminSettings(settings) {
  return request('/api/admin/settings', {
    method: 'PUT',
    body: JSON.stringify(settings)
  });
}

export async function listAdminUsers() {
  return request('/api/admin/users');
}

// Offline cache helpers
export function getOfflineEntries() {
  try {
    const cached = localStorage.getItem(OFFLINE_CACHE_KEY);
    return cached ? JSON.parse(cached) : [];
  } catch {
    return [];
  }
}

export function getOfflineUser() {
  try {
    const cached = localStorage.getItem(OFFLINE_USER_KEY);
    return cached ? JSON.parse(cached) : null;
  } catch {
    return null;
  }
}

export function saveOfflineUser(user) {
  try {
    localStorage.setItem(OFFLINE_USER_KEY, JSON.stringify(user));
  } catch { /* ignore */ }
}

export function clearOfflineData() {
  localStorage.removeItem(OFFLINE_CACHE_KEY);
  localStorage.removeItem(OFFLINE_USER_KEY);
}

export { API_BASE_URL, TOKEN_KEY, getToken, saveToken, clearToken };