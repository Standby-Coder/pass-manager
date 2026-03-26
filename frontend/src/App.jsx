import { useEffect, useMemo, useState } from 'react';
import {
  clearToken,
  createPasswordEntry,
  deletePasswordEntry,
  fetchPasswords,
  getToken,
  loginUser,
  registerUser,
  saveToken
} from './api';

const emptyLoginForm = {
  email: '',
  password: ''
};

const emptyRegisterForm = {
  email: '',
  password: '',
  display_name: ''
};

const emptyEntryForm = {
  title: '',
  username: '',
  password: '',
  url: '',
  notes: '',
  category: ''
};

function normalizeUser(payload) {
  return payload?.user || null;
}

function normalizeToken(payload) {
  return payload?.token || null;
}

function normalizeEntries(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (Array.isArray(payload?.entries)) {
    return payload.entries;
  }

  if (Array.isArray(payload?.passwords)) {
    return payload.passwords;
  }

  return [];
}

function App() {
  const [mode, setMode] = useState('login');
  const [token, setToken] = useState(() => getToken() || '');
  const [user, setUser] = useState(null);
  const [entries, setEntries] = useState([]);
  const [loginForm, setLoginForm] = useState(emptyLoginForm);
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm);
  const [entryForm, setEntryForm] = useState(emptyEntryForm);
  const [authLoading, setAuthLoading] = useState(false);
  const [entriesLoading, setEntriesLoading] = useState(false);
  const [entrySubmitting, setEntrySubmitting] = useState(false);
  const [error, setError] = useState('');

  const isAuthenticated = useMemo(() => Boolean(token), [token]);

  useEffect(() => {
    if (!isAuthenticated) {
      setEntries([]);
      setUser(null);
      return;
    }

    loadEntries();
  }, [isAuthenticated]);

  async function loadEntries() {
    setEntriesLoading(true);
    setError('');

    try {
      const data = await fetchPasswords();
      setEntries(normalizeEntries(data));
    } catch (err) {
      if (/unauthorized|token|forbidden/i.test(err.message)) {
        handleLogout();
      }
      setError(err.message);
    } finally {
      setEntriesLoading(false);
    }
  }

  async function handleRegister(event) {
    event.preventDefault();
    setAuthLoading(true);
    setError('');

    try {
      const payload = {
        email: registerForm.email.trim(),
        password: registerForm.password,
        display_name: registerForm.display_name.trim()
      };

      if (!payload.display_name) {
        delete payload.display_name;
      }

      const data = await registerUser(payload);
      const nextToken = normalizeToken(data);

      if (!nextToken) {
        throw new Error('Registration succeeded but no token was returned');
      }

      saveToken(nextToken);
      setToken(nextToken);
      setUser(normalizeUser(data));
      setRegisterForm(emptyRegisterForm);
    } catch (err) {
      setError(err.message);
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    setAuthLoading(true);
    setError('');

    try {
      const data = await loginUser({
        email: loginForm.email.trim(),
        password: loginForm.password
      });

      const nextToken = normalizeToken(data);

      if (!nextToken) {
        throw new Error('Login succeeded but no token was returned');
      }

      saveToken(nextToken);
      setToken(nextToken);
      setUser(normalizeUser(data));
      setLoginForm(emptyLoginForm);
    } catch (err) {
      setError(err.message);
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleCreateEntry(event) {
    event.preventDefault();
    setEntrySubmitting(true);
    setError('');

    try {
      const payload = {
        title: entryForm.title.trim(),
        username: entryForm.username.trim(),
        password: entryForm.password,
        url: entryForm.url.trim(),
        notes: entryForm.notes.trim(),
        category: entryForm.category.trim()
      };

      const data = await createPasswordEntry(payload);
      const createdEntry = data?.entry || data?.password || data;

      setEntries((current) => [createdEntry, ...current]);
      setEntryForm(emptyEntryForm);
    } catch (err) {
      setError(err.message);
    } finally {
      setEntrySubmitting(false);
    }
  }

  async function handleDeleteEntry(id) {
    setError('');

    try {
      await deletePasswordEntry(id);
      setEntries((current) => current.filter((entry) => entry.id !== id));
    } catch (err) {
      setError(err.message);
    }
  }

  function handleLogout() {
    clearToken();
    setToken('');
    setUser(null);
    setEntries([]);
    setEntryForm(emptyEntryForm);
    setLoginForm(emptyLoginForm);
    setRegisterForm(emptyRegisterForm);
  }

  return (
    <div className="app-shell">
      <div className="app-card">
        <header className="app-header">
          <div>
            <p className="eyebrow">Phase 1 MVP</p>
            <h1>Password Manager</h1>
            <p className="subtitle">Register, log in, and manage a simple password vault.</p>
          </div>

          {isAuthenticated ? (
            <button className="secondary-button" type="button" onClick={handleLogout}>
              Logout
            </button>
          ) : null}
        </header>

        {error ? <div className="alert error-alert">{error}</div> : null}

        {!isAuthenticated ? (
          <section className="auth-section">
            <div className="auth-tabs">
              <button
                type="button"
                className={mode === 'login' ? 'tab-button active' : 'tab-button'}
                onClick={() => setMode('login')}
              >
                Login
              </button>
              <button
                type="button"
                className={mode === 'register' ? 'tab-button active' : 'tab-button'}
                onClick={() => setMode('register')}
              >
                Register
              </button>
            </div>

            {mode === 'login' ? (
              <form className="panel form-grid" onSubmit={handleLogin}>
                <label>
                  Email
                  <input
                    type="email"
                    value={loginForm.email}
                    onChange={(event) =>
                      setLoginForm((current) => ({ ...current, email: event.target.value }))
                    }
                    required
                  />
                </label>

                <label>
                  Password
                  <input
                    type="password"
                    value={loginForm.password}
                    onChange={(event) =>
                      setLoginForm((current) => ({ ...current, password: event.target.value }))
                    }
                    required
                  />
                </label>

                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? 'Signing in...' : 'Login'}
                </button>
              </form>
            ) : (
              <form className="panel form-grid" onSubmit={handleRegister}>
                <label>
                  Display name
                  <input
                    type="text"
                    value={registerForm.display_name}
                    onChange={(event) =>
                      setRegisterForm((current) => ({
                        ...current,
                        display_name: event.target.value
                      }))
                    }
                    placeholder="Optional"
                  />
                </label>

                <label>
                  Email
                  <input
                    type="email"
                    value={registerForm.email}
                    onChange={(event) =>
                      setRegisterForm((current) => ({ ...current, email: event.target.value }))
                    }
                    required
                  />
                </label>

                <label>
                  Password
                  <input
                    type="password"
                    value={registerForm.password}
                    onChange={(event) =>
                      setRegisterForm((current) => ({ ...current, password: event.target.value }))
                    }
                    required
                  />
                </label>

                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? 'Creating account...' : 'Register'}
                </button>
              </form>
            )}
          </section>
        ) : (
          <main className="vault-layout">
            <section className="panel">
              <div className="section-heading">
                <div>
                  <h2>New Password Entry</h2>
                  <p className="muted-text">
                    Signed in as {user?.display_name || user?.email || 'current user'}
                  </p>
                </div>
              </div>

              <form className="form-grid" onSubmit={handleCreateEntry}>
                <label>
                  Title
                  <input
                    type="text"
                    value={entryForm.title}
                    onChange={(event) =>
                      setEntryForm((current) => ({ ...current, title: event.target.value }))
                    }
                    required
                  />
                </label>

                <label>
                  Username
                  <input
                    type="text"
                    value={entryForm.username}
                    onChange={(event) =>
                      setEntryForm((current) => ({ ...current, username: event.target.value }))
                    }
                  />
                </label>

                <label>
                  Password
                  <input
                    type="text"
                    value={entryForm.password}
                    onChange={(event) =>
                      setEntryForm((current) => ({ ...current, password: event.target.value }))
                    }
                    required
                  />
                </label>

                <label>
                  URL
                  <input
                    type="url"
                    value={entryForm.url}
                    onChange={(event) =>
                      setEntryForm((current) => ({ ...current, url: event.target.value }))
                    }
                    placeholder="https://example.com"
                  />
                </label>

                <label>
                  Category
                  <input
                    type="text"
                    value={entryForm.category}
                    onChange={(event) =>
                      setEntryForm((current) => ({ ...current, category: event.target.value }))
                    }
                  />
                </label>

                <label className="full-width">
                  Notes
                  <textarea
                    rows="4"
                    value={entryForm.notes}
                    onChange={(event) =>
                      setEntryForm((current) => ({ ...current, notes: event.target.value }))
                    }
                  />
                </label>

                <button className="primary-button" type="submit" disabled={entrySubmitting}>
                  {entrySubmitting ? 'Saving...' : 'Save Entry'}
                </button>
              </form>
            </section>

            <section className="panel">
              <div className="section-heading">
                <div>
                  <h2>Your Vault</h2>
                  <p className="muted-text">{entries.length} entr{entries.length === 1 ? 'y' : 'ies'}</p>
                </div>
                <button className="secondary-button" type="button" onClick={loadEntries} disabled={entriesLoading}>
                  {entriesLoading ? 'Refreshing...' : 'Refresh'}
                </button>
              </div>

              {entriesLoading ? <p className="status-text">Loading entries...</p> : null}

              {!entriesLoading && entries.length === 0 ? (
                <p className="status-text">No password entries yet. Create your first one above.</p>
              ) : null}

              <div className="entry-list">
                {entries.map((entry) => (
                  <article className="entry-card" key={entry.id}>
                    <div className="entry-card-header">
                      <div>
                        <h3>{entry.title}</h3>
                        <p className="muted-text">{entry.category || 'Uncategorized'}</p>
                      </div>
                      <button
                        className="danger-button"
                        type="button"
                        onClick={() => handleDeleteEntry(entry.id)}
                      >
                        Delete
                      </button>
                    </div>

                    <dl className="entry-details">
                      <div>
                        <dt>Username</dt>
                        <dd>{entry.username || '—'}</dd>
                      </div>
                      <div>
                        <dt>Password</dt>
                        <dd>{entry.password || '—'}</dd>
                      </div>
                      <div>
                        <dt>URL</dt>
                        <dd>
                          {entry.url ? (
                            <a href={entry.url} target="_blank" rel="noreferrer">
                              {entry.url}
                            </a>
                          ) : (
                            '—'
                          )}
                        </dd>
                      </div>
                      <div className="full-width">
                        <dt>Notes</dt>
                        <dd>{entry.notes || '—'}</dd>
                      </div>
                    </dl>
                  </article>
                ))}
              </div>
            </section>
          </main>
        )}
      </div>
    </div>
  );
}

export default App;