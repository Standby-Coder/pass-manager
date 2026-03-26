const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8080';
const TOKEN_KEY = 'auth_token';

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

export async function fetchPasswords() {
  return request('/api/passwords');
}

export async function createPasswordEntry(payload) {
  return request('/api/passwords', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export async function deletePasswordEntry(id) {
  return request(`/api/passwords/${id}`, {
    method: 'DELETE'
  });
}

export { API_BASE_URL, TOKEN_KEY, getToken, saveToken, clearToken };