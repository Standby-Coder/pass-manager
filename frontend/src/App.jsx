import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  clearOfflineData,
  clearToken,
  confirmEnableMFA,
  confirmPasswordReset,
  createPasswordEntry,
  deletePasswordEntry,
  disableMFA,
  enableMFA,
  exportVault,
  fetchPasswords,
  fetchSecurityPolicy,
  generatePassword as apiGeneratePassword,
  getAdminSettings,
  getOfflineEntries,
  getToken,
  importVault,
  listAdminUsers,
  loginUser,
  registerUser,
  requestPasswordReset,
  saveOfflineUser,
  saveToken,
  updateAdminSettings,
  updatePasswordEntry,
  verifyMFA
} from './api';

const emptyLoginForm = { email: '', password: '' };
const emptyRegisterForm = { email: '', password: '', display_name: '' };
const emptyEntryForm = { title: '', username: '', password: '', url: '', notes: '', category: '' };
const emptyResetRequestForm = { email: '' };
const emptyResetConfirmForm = { token: '', new_password: '' };
const emptyMFAForm = { mfa_token: '', code: '' };

function normalizeUser(payload) {
  return payload?.user || null;
}
function normalizeToken(payload) {
  return payload?.token || null;
}
function normalizeEntries(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.entries)) return payload.entries;
  if (Array.isArray(payload?.passwords)) return payload.passwords;
  return [];
}

// --- Password Strength ---
function computePasswordStrength(password, policy) {
  if (!password) return { score: 0, label: '', errors: [] };
  let score = 0;
  const errors = [];
  const minLen = policy?.min_password_length || 8;

  if (password.length >= minLen) score += 1;
  else errors.push(`At least ${minLen} characters`);

  if (/[A-Z]/.test(password)) score += 1;
  else if (policy?.require_uppercase) errors.push('Uppercase letter required');

  if (/[a-z]/.test(password)) score += 1;
  else if (policy?.require_lowercase) errors.push('Lowercase letter required');

  if (/[0-9]/.test(password)) score += 1;
  else if (policy?.require_digit) errors.push('Digit required');

  if (/[^a-zA-Z0-9]/.test(password)) score += 1;
  else if (policy?.require_special_char) errors.push('Special character required');

  // Bonus for extra length
  if (password.length >= minLen + 4) score += 1;
  if (password.length >= minLen + 8) score += 1;

  const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong', 'Excellent'];
  return { score: Math.min(score, 7), label: labels[Math.min(score, 7)], errors };
}

function PasswordStrengthMeter({ password, policy }) {
  const { score, label, errors } = computePasswordStrength(password, policy);
  const colors = ['#475569', '#ef4444', '#f97316', '#eab308', '#22c55e', '#10b981', '#06b6d4', '#8b5cf6'];
  const pct = (score / 7) * 100;

  return (
    <div className="strength-meter">
      <div className="strength-bar-bg">
        <div className="strength-bar-fill" style={{ width: `${pct}%`, background: colors[score] }} />
      </div>
      <span className="strength-label" style={{ color: colors[score] }}>
        {label}
      </span>
      {errors.length > 0 && (
        <ul className="strength-errors">
          {errors.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

// --- Show/Hide Password ---
function PasswordField({ value, onChange, required, placeholder, id }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="password-field">
      <input
        id={id}
        type={visible ? 'text' : 'password'}
        value={value}
        onChange={onChange}
        required={required}
        placeholder={placeholder}
        autoComplete="off"
      />
      <button type="button" className="toggle-visibility" onClick={() => setVisible((v) => !v)} tabIndex={-1}>
        {visible ? 'Hide' : 'Show'}
      </button>
    </div>
  );
}

function MaskedPassword({ value }) {
  const [visible, setVisible] = useState(false);
  return (
    <span className="masked-password">
      <span>{visible ? value : '••••••••'}</span>
      <button type="button" className="toggle-visibility small" onClick={() => setVisible((v) => !v)} tabIndex={-1}>
        {visible ? 'Hide' : 'Show'}
      </button>
    </span>
  );
}

function App() {
  const [mode, setMode] = useState('login'); // login | register | reset-request | reset-confirm | mfa-verify
  const [token, setToken] = useState(() => getToken() || '');
  const [user, setUser] = useState(null);
  const [entries, setEntries] = useState([]);
  const [loginForm, setLoginForm] = useState(emptyLoginForm);
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm);
  const [entryForm, setEntryForm] = useState(emptyEntryForm);
  const [editingId, setEditingId] = useState(null);
  const [resetRequestForm, setResetRequestForm] = useState(emptyResetRequestForm);
  const [resetConfirmForm, setResetConfirmForm] = useState(emptyResetConfirmForm);
  const [mfaForm, setMfaForm] = useState(emptyMFAForm);
  const [authLoading, setAuthLoading] = useState(false);
  const [entriesLoading, setEntriesLoading] = useState(false);
  const [entrySubmitting, setEntrySubmitting] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [policy, setPolicy] = useState(null);
  const [isOffline, setIsOffline] = useState(!navigator.onLine);
  const [activeTab, setActiveTab] = useState('vault'); // vault | export | admin | mfa-settings
  const [exportPassword, setExportPassword] = useState('');
  const [importPassword, setImportPassword] = useState('');
  const [importData, setImportData] = useState('');
  const [adminSettings, setAdminSettings] = useState(null);
  const [adminUsers, setAdminUsers] = useState([]);
  const [mfaEnableCode, setMfaEnableCode] = useState('');
  const [mfaDisablePassword, setMfaDisablePassword] = useState('');
  const [pendingMfaCode, setPendingMfaCode] = useState('');

  const isAuthenticated = useMemo(() => Boolean(token), [token]);

  // --- Offline detection ---
  useEffect(() => {
    const online = () => setIsOffline(false);
    const offline = () => setIsOffline(true);
    window.addEventListener('online', online);
    window.addEventListener('offline', offline);
    return () => {
      window.removeEventListener('online', online);
      window.removeEventListener('offline', offline);
    };
  }, []);

  const handleLogout = useCallback(() => {
    clearToken();
    clearOfflineData();
    setToken('');
    setUser(null);
    setEntries([]);
    setEntryForm(emptyEntryForm);
    setLoginForm(emptyLoginForm);
    setRegisterForm(emptyRegisterForm);
    setSearchQuery('');
    setCategoryFilter('');
    setEditingId(null);
    setActiveTab('vault');
  }, []);

  // --- Inactivity Logout ---
  const inactivityTimerRef = useRef(null);
  const inactivityTimeout = (policy?.inactivity_timeout || 900) * 1000; // seconds -> ms

  const resetInactivityTimer = useCallback(() => {
    if (!isAuthenticated) return;
    if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    inactivityTimerRef.current = setTimeout(() => {
      handleLogout();
      setError('Logged out due to inactivity');
    }, inactivityTimeout);
  }, [isAuthenticated, inactivityTimeout, handleLogout]);

  useEffect(() => {
    if (!isAuthenticated) {
      if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
      return;
    }
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    events.forEach((ev) => window.addEventListener(ev, resetInactivityTimer));
    resetInactivityTimer();
    return () => {
      events.forEach((ev) => window.removeEventListener(ev, resetInactivityTimer));
      if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    };
  }, [isAuthenticated, resetInactivityTimer]);

  // --- Load security policy ---
  useEffect(() => {
    fetchSecurityPolicy().then(setPolicy).catch(() => {});
  }, []);

  // --- Load entries ---
  useEffect(() => {
    if (!isAuthenticated) {
      setEntries([]);
      setUser(null);
      return;
    }
    loadEntries();
  }, [isAuthenticated]);

  async function loadEntries() {
    if (isOffline) {
      setEntries(getOfflineEntries());
      return;
    }
    setEntriesLoading(true);
    setError('');
    try {
      const data = await fetchPasswords(searchQuery, categoryFilter);
      setEntries(normalizeEntries(data));
    } catch (err) {
      if (/unauthorized|token|forbidden/i.test(err.message)) handleLogout();
      // Fall back to offline cache on network error
      if (err.message === 'Failed to fetch' || err.name === 'TypeError') {
        setEntries(getOfflineEntries());
        setIsOffline(true);
      } else {
        setError(err.message);
      }
    } finally {
      setEntriesLoading(false);
    }
  }

  // Reload when search/filter changes
  useEffect(() => {
    if (isAuthenticated) loadEntries();
  }, [searchQuery, categoryFilter, isAuthenticated]);

  // --- Auth handlers ---
  async function handleRegister(event) {
    event.preventDefault();
    setAuthLoading(true);
    setError('');
    setSuccessMessage('');
    try {
      const payload = {
        email: registerForm.email.trim(),
        password: registerForm.password,
        display_name: registerForm.display_name.trim()
      };
      if (!payload.display_name) delete payload.display_name;
      const data = await registerUser(payload);
      const nextToken = normalizeToken(data);
      if (!nextToken) throw new Error('Registration succeeded but no token was returned');
      saveToken(nextToken);
      setToken(nextToken);
      const u = normalizeUser(data);
      setUser(u);
      saveOfflineUser(u);
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
    setSuccessMessage('');
    try {
      const data = await loginUser({ email: loginForm.email.trim(), password: loginForm.password });

      // Check if MFA is required
      if (data?.mfa_required) {
        setMfaForm({ mfa_token: data.mfa_token, code: '' });
        setPendingMfaCode(data.mfa_code || ''); // MVP: code returned in response
        setMode('mfa-verify');
        if (data.mfa_code) {
          setSuccessMessage(`MFA Code (MVP): ${data.mfa_code}`);
        } else {
          setSuccessMessage('Check your email for the MFA code.');
        }
        setLoginForm(emptyLoginForm);
        return;
      }

      const nextToken = normalizeToken(data);
      if (!nextToken) throw new Error('Login succeeded but no token was returned');
      saveToken(nextToken);
      setToken(nextToken);
      const u = normalizeUser(data);
      setUser(u);
      saveOfflineUser(u);
      setLoginForm(emptyLoginForm);
    } catch (err) {
      setError(err.message);
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleMFAVerify(event) {
    event.preventDefault();
    setAuthLoading(true);
    setError('');
    setSuccessMessage('');
    try {
      const data = await verifyMFA(mfaForm.mfa_token, mfaForm.code);
      const nextToken = normalizeToken(data);
      if (!nextToken) throw new Error('MFA verification succeeded but no token was returned');
      saveToken(nextToken);
      setToken(nextToken);
      const u = normalizeUser(data);
      setUser(u);
      saveOfflineUser(u);
      setMfaForm(emptyMFAForm);
      setPendingMfaCode('');
      setMode('login');
    } catch (err) {
      setError(err.message);
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleResetRequest(event) {
    event.preventDefault();
    setAuthLoading(true);
    setError('');
    setSuccessMessage('');
    try {
      const data = await requestPasswordReset(resetRequestForm.email.trim());
      if (data?.reset_token) {
        setResetConfirmForm({ token: data.reset_token, new_password: '' });
        setMode('reset-confirm');
        setSuccessMessage('Reset token generated. Enter it below with your new password.');
      } else {
        setSuccessMessage('If the email exists, a reset link has been sent.');
      }
      setResetRequestForm(emptyResetRequestForm);
    } catch (err) {
      setError(err.message);
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleResetConfirm(event) {
    event.preventDefault();
    setAuthLoading(true);
    setError('');
    setSuccessMessage('');
    try {
      await confirmPasswordReset(resetConfirmForm.token, resetConfirmForm.new_password);
      setSuccessMessage('Password has been reset. You can now log in.');
      setResetConfirmForm(emptyResetConfirmForm);
      setMode('login');
    } catch (err) {
      setError(err.message);
    } finally {
      setAuthLoading(false);
    }
  }

  // --- Entry handlers ---
  async function handleCreateOrUpdateEntry(event) {
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
      if (editingId) {
        const data = await updatePasswordEntry(editingId, payload);
        const updatedEntry = data?.entry || data;
        setEntries((cur) => cur.map((e) => (e.id === editingId ? updatedEntry : e)));
        setEditingId(null);
      } else {
        const data = await createPasswordEntry(payload);
        const createdEntry = data?.entry || data;
        setEntries((cur) => [createdEntry, ...cur]);
      }
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
      setEntries((cur) => cur.filter((e) => e.id !== id));
    } catch (err) {
      setError(err.message);
    }
  }

  function handleEditEntry(entry) {
    setEditingId(entry.id);
    setEntryForm({
      title: entry.title || '',
      username: entry.username || '',
      password: entry.password || '',
      url: entry.url || '',
      notes: entry.notes || '',
      category: entry.category || ''
    });
  }

  function handleCancelEdit() {
    setEditingId(null);
    setEntryForm(emptyEntryForm);
  }

  async function handleGeneratePassword(target) {
    try {
      const data = await apiGeneratePassword();
      if (target === 'entry') {
        setEntryForm((cur) => ({ ...cur, password: data.password }));
      } else if (target === 'register') {
        setRegisterForm((cur) => ({ ...cur, password: data.password }));
      } else if (target === 'reset') {
        setResetConfirmForm((cur) => ({ ...cur, new_password: data.password }));
      }
    } catch {
      setError('Failed to generate password');
    }
  }

  // --- Export/Import handlers ---
  async function handleExport(event) {
    event.preventDefault();
    setError('');
    setSuccessMessage('');
    try {
      const data = await exportVault(exportPassword);
      // Create download
      const blob = new Blob([data.data], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'vault-export.enc';
      a.click();
      URL.revokeObjectURL(url);
      setSuccessMessage(`Vault exported: ${data.count} entries`);
      setExportPassword('');
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleImport(event) {
    event.preventDefault();
    setError('');
    setSuccessMessage('');
    try {
      const data = await importVault(importPassword, importData);
      setSuccessMessage(`Imported ${data.imported} of ${data.total} entries`);
      setImportPassword('');
      setImportData('');
      loadEntries();
    } catch (err) {
      setError(err.message);
    }
  }

  function handleImportFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => setImportData(e.target.result);
    reader.readAsText(file);
  }

  // --- MFA settings handlers ---
  async function handleEnableMFA() {
    setError('');
    setSuccessMessage('');
    try {
      const data = await enableMFA();
      setMfaEnableCode('');
      setSuccessMessage(`MFA Code (MVP): ${data.code}. Enter the code below to confirm.`);
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleConfirmEnableMFA(event) {
    event.preventDefault();
    setError('');
    setSuccessMessage('');
    try {
      await confirmEnableMFA(mfaEnableCode);
      setSuccessMessage('MFA has been enabled.');
      setMfaEnableCode('');
      setUser((u) => u ? { ...u, mfa_enabled: true } : u);
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleDisableMFA(event) {
    event.preventDefault();
    setError('');
    setSuccessMessage('');
    try {
      await disableMFA(mfaDisablePassword);
      setSuccessMessage('MFA has been disabled.');
      setMfaDisablePassword('');
      setUser((u) => u ? { ...u, mfa_enabled: false } : u);
    } catch (err) {
      setError(err.message);
    }
  }

  // --- Admin handlers ---
  async function loadAdminSettings() {
    try {
      const data = await getAdminSettings();
      setAdminSettings(data);
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadAdminUsers() {
    try {
      const data = await listAdminUsers();
      setAdminUsers(data?.users || []);
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleUpdateAdminSettings(event) {
    event.preventDefault();
    setError('');
    setSuccessMessage('');
    try {
      await updateAdminSettings(adminSettings);
      setSuccessMessage('Settings updated.');
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    if (activeTab === 'admin' && user?.is_admin) {
      loadAdminSettings();
      loadAdminUsers();
    }
  }, [activeTab]);

  const categories = useMemo(() => {
    const cats = new Set(entries.map((e) => e.category).filter(Boolean));
    return Array.from(cats).sort();
  }, [entries]);

  return (
    <div className="app-shell">
      <div className="app-card">
        <header className="app-header">
          <div>
            <p className="eyebrow">Phase 3</p>
            <h1>Password Manager</h1>
            <p className="subtitle">Encrypted vault with sync, MFA &amp; offline access.</p>
            {isOffline && <span className="offline-badge">Offline Mode</span>}
          </div>
          {isAuthenticated && (
            <button className="secondary-button" type="button" onClick={handleLogout}>
              Logout
            </button>
          )}
        </header>

        {error && <div className="alert error-alert">{error}</div>}
        {successMessage && <div className="alert success-alert">{successMessage}</div>}

        {!isAuthenticated ? (
          <section className="auth-section">
            <div className="auth-tabs">
              <button
                type="button"
                className={mode === 'login' ? 'tab-button active' : 'tab-button'}
                onClick={() => { setMode('login'); setError(''); setSuccessMessage(''); }}
              >
                Login
              </button>
              <button
                type="button"
                className={mode === 'register' ? 'tab-button active' : 'tab-button'}
                onClick={() => { setMode('register'); setError(''); setSuccessMessage(''); }}
              >
                Register
              </button>
              <button
                type="button"
                className={mode === 'reset-request' || mode === 'reset-confirm' ? 'tab-button active' : 'tab-button'}
                onClick={() => { setMode('reset-request'); setError(''); setSuccessMessage(''); }}
              >
                Reset Password
              </button>
            </div>

            {mode === 'login' && (
              <form className="panel form-grid" onSubmit={handleLogin}>
                <label>
                  Email
                  <input
                    type="email"
                    value={loginForm.email}
                    onChange={(e) => setLoginForm((c) => ({ ...c, email: e.target.value }))}
                    required
                  />
                </label>
                <label>
                  Password
                  <PasswordField
                    value={loginForm.password}
                    onChange={(e) => setLoginForm((c) => ({ ...c, password: e.target.value }))}
                    required
                  />
                </label>
                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? 'Signing in...' : 'Login'}
                </button>
              </form>
            )}

            {mode === 'mfa-verify' && (
              <form className="panel form-grid" onSubmit={handleMFAVerify}>
                <label>
                  MFA Code
                  <input
                    type="text"
                    value={mfaForm.code}
                    onChange={(e) => setMfaForm((c) => ({ ...c, code: e.target.value }))}
                    required
                    placeholder="Enter 6-digit code"
                    maxLength={6}
                    autoComplete="one-time-code"
                  />
                </label>
                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? 'Verifying...' : 'Verify MFA'}
                </button>
                <button type="button" className="secondary-button" onClick={() => { setMode('login'); setError(''); setSuccessMessage(''); }}>
                  Back to Login
                </button>
              </form>
            )}

            {mode === 'register' && (
              <form className="panel form-grid" onSubmit={handleRegister}>
                <label>
                  Display name
                  <input
                    type="text"
                    value={registerForm.display_name}
                    onChange={(e) => setRegisterForm((c) => ({ ...c, display_name: e.target.value }))}
                    placeholder="Optional"
                  />
                </label>
                <label>
                  Email
                  <input
                    type="email"
                    value={registerForm.email}
                    onChange={(e) => setRegisterForm((c) => ({ ...c, email: e.target.value }))}
                    required
                  />
                </label>
                <label>
                  Password
                  <div className="password-with-generate">
                    <PasswordField
                      value={registerForm.password}
                      onChange={(e) => setRegisterForm((c) => ({ ...c, password: e.target.value }))}
                      required
                    />
                    <button type="button" className="generate-btn" onClick={() => handleGeneratePassword('register')}>
                      Generate
                    </button>
                  </div>
                  <PasswordStrengthMeter password={registerForm.password} policy={policy} />
                </label>
                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? 'Creating account...' : 'Register'}
                </button>
              </form>
            )}

            {mode === 'reset-request' && (
              <form className="panel form-grid" onSubmit={handleResetRequest}>
                <label>
                  Email
                  <input
                    type="email"
                    value={resetRequestForm.email}
                    onChange={(e) => setResetRequestForm((c) => ({ ...c, email: e.target.value }))}
                    required
                  />
                </label>
                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? 'Requesting...' : 'Request Reset'}
                </button>
              </form>
            )}

            {mode === 'reset-confirm' && (
              <form className="panel form-grid" onSubmit={handleResetConfirm}>
                <label>
                  Reset Token
                  <input
                    type="text"
                    value={resetConfirmForm.token}
                    onChange={(e) => setResetConfirmForm((c) => ({ ...c, token: e.target.value }))}
                    required
                  />
                </label>
                <label>
                  New Password
                  <div className="password-with-generate">
                    <PasswordField
                      value={resetConfirmForm.new_password}
                      onChange={(e) => setResetConfirmForm((c) => ({ ...c, new_password: e.target.value }))}
                      required
                    />
                    <button type="button" className="generate-btn" onClick={() => handleGeneratePassword('reset')}>
                      Generate
                    </button>
                  </div>
                  <PasswordStrengthMeter password={resetConfirmForm.new_password} policy={policy} />
                </label>
                <button className="primary-button" type="submit" disabled={authLoading}>
                  {authLoading ? 'Resetting...' : 'Reset Password'}
                </button>
              </form>
            )}
          </section>
        ) : (
          <>
            {/* Authenticated tabs */}
            <div className="main-tabs">
              <button type="button" className={activeTab === 'vault' ? 'tab-button active' : 'tab-button'} onClick={() => setActiveTab('vault')}>Vault</button>
              <button type="button" className={activeTab === 'export' ? 'tab-button active' : 'tab-button'} onClick={() => setActiveTab('export')}>Export / Import</button>
              <button type="button" className={activeTab === 'mfa-settings' ? 'tab-button active' : 'tab-button'} onClick={() => setActiveTab('mfa-settings')}>MFA</button>
              {user?.is_admin && (
                <button type="button" className={activeTab === 'admin' ? 'tab-button active' : 'tab-button'} onClick={() => setActiveTab('admin')}>Admin</button>
              )}
            </div>

            {activeTab === 'vault' && (
              <main className="vault-layout">
                <section className="panel">
                  <div className="section-heading">
                    <div>
                      <h2>{editingId ? 'Edit Entry' : 'New Password Entry'}</h2>
                      <p className="muted-text">
                        Signed in as {user?.display_name || user?.email || 'current user'}
                        {user?.is_admin && ' (Admin)'}
                      </p>
                    </div>
                    {editingId && (
                      <button className="secondary-button" type="button" onClick={handleCancelEdit}>
                        Cancel
                      </button>
                    )}
                  </div>

                  {!isOffline ? (
                    <form className="form-grid" onSubmit={handleCreateOrUpdateEntry}>
                      <label>
                        Title
                        <input type="text" value={entryForm.title} onChange={(e) => setEntryForm((c) => ({ ...c, title: e.target.value }))} required maxLength={255} />
                      </label>
                      <label>
                        Username
                        <input type="text" value={entryForm.username} onChange={(e) => setEntryForm((c) => ({ ...c, username: e.target.value }))} maxLength={255} />
                      </label>
                      <label>
                        Password
                        <div className="password-with-generate">
                          <PasswordField value={entryForm.password} onChange={(e) => setEntryForm((c) => ({ ...c, password: e.target.value }))} required />
                          <button type="button" className="generate-btn" onClick={() => handleGeneratePassword('entry')}>Generate</button>
                        </div>
                        <PasswordStrengthMeter password={entryForm.password} policy={policy} />
                      </label>
                      <label>
                        URL
                        <input type="url" value={entryForm.url} onChange={(e) => setEntryForm((c) => ({ ...c, url: e.target.value }))} placeholder="https://example.com" maxLength={512} />
                      </label>
                      <label>
                        Category
                        <input type="text" value={entryForm.category} onChange={(e) => setEntryForm((c) => ({ ...c, category: e.target.value }))} maxLength={100} />
                      </label>
                      <label className="full-width">
                        Notes
                        <textarea rows="4" value={entryForm.notes} onChange={(e) => setEntryForm((c) => ({ ...c, notes: e.target.value }))} maxLength={5000} />
                      </label>
                      <button className="primary-button" type="submit" disabled={entrySubmitting}>
                        {entrySubmitting ? 'Saving...' : editingId ? 'Update Entry' : 'Save Entry'}
                      </button>
                    </form>
                  ) : (
                    <p className="muted-text">Read-only in offline mode. Last 10 cached entries shown.</p>
                  )}
                </section>

                <section className="panel">
                  <div className="section-heading">
                    <div>
                      <h2>Your Vault</h2>
                      <p className="muted-text">
                        {entries.length} entr{entries.length === 1 ? 'y' : 'ies'}
                        {isOffline && ' (cached)'}
                      </p>
                    </div>
                    <button className="secondary-button" type="button" onClick={loadEntries} disabled={entriesLoading || isOffline}>
                      {entriesLoading ? 'Refreshing...' : 'Refresh'}
                    </button>
                  </div>

                  <div className="search-filter-bar">
                    <input type="text" placeholder="Search entries..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="search-input" disabled={isOffline} />
                    <select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} className="category-select" disabled={isOffline}>
                      <option value="">All categories</option>
                      {categories.map((cat) => (<option key={cat} value={cat}>{cat}</option>))}
                    </select>
                  </div>

                  {entriesLoading && <p className="status-text">Loading entries...</p>}
                  {!entriesLoading && entries.length === 0 && <p className="status-text">No password entries found.</p>}

                  <div className="entry-list">
                    {entries.map((entry) => (
                      <article className="entry-card" key={entry.id}>
                        <div className="entry-card-header">
                          <div>
                            <h3>{entry.title}</h3>
                            <p className="muted-text">{entry.category || 'Uncategorized'}</p>
                          </div>
                          {!isOffline && (
                            <div className="entry-actions">
                              <button className="secondary-button" type="button" onClick={() => handleEditEntry(entry)}>Edit</button>
                              <button className="danger-button" type="button" onClick={() => handleDeleteEntry(entry.id)}>Delete</button>
                            </div>
                          )}
                        </div>
                        <dl className="entry-details">
                          <div><dt>Username</dt><dd>{entry.username || '—'}</dd></div>
                          <div><dt>Password</dt><dd><MaskedPassword value={entry.password || '—'} /></dd></div>
                          <div>
                            <dt>URL</dt>
                            <dd>{entry.url ? (() => { try { const u = new URL(entry.url); return ['http:', 'https:'].includes(u.protocol) ? <a href={entry.url} target="_blank" rel="noreferrer">{entry.url}</a> : entry.url; } catch { return entry.url; } })() : '—'}</dd>
                          </div>
                          <div className="full-width"><dt>Notes</dt><dd>{entry.notes || '—'}</dd></div>
                        </dl>
                      </article>
                    ))}
                  </div>
                </section>
              </main>
            )}

            {activeTab === 'export' && (
              <section className="settings-section">
                <div className="panel">
                  <h2>Export Vault</h2>
                  <p className="muted-text">Download an encrypted copy of your vault, protected with your account password.</p>
                  <form className="form-grid" onSubmit={handleExport}>
                    <label>
                      Confirm Password
                      <PasswordField value={exportPassword} onChange={(e) => setExportPassword(e.target.value)} required placeholder="Your account password" />
                    </label>
                    <button className="primary-button" type="submit">Export Vault</button>
                  </form>
                </div>

                <div className="panel">
                  <h2>Import Vault</h2>
                  <p className="muted-text">Import entries from an exported vault file.</p>
                  <form className="form-grid" onSubmit={handleImport}>
                    <label>
                      Confirm Password
                      <PasswordField value={importPassword} onChange={(e) => setImportPassword(e.target.value)} required placeholder="Password used during export" />
                    </label>
                    <label>
                      Vault File
                      <input type="file" onChange={handleImportFile} accept=".enc" />
                    </label>
                    {importData && <p className="muted-text">File loaded ({importData.length} bytes)</p>}
                    <button className="primary-button" type="submit" disabled={!importData}>Import Vault</button>
                  </form>
                </div>
              </section>
            )}

            {activeTab === 'mfa-settings' && (
              <section className="settings-section">
                <div className="panel">
                  <h2>Multi-Factor Authentication</h2>
                  <p className="muted-text">
                    Status: <strong>{user?.mfa_enabled ? 'Enabled' : 'Disabled'}</strong>
                  </p>

                  {!user?.mfa_enabled ? (
                    <>
                      <button className="primary-button" type="button" onClick={handleEnableMFA} style={{ marginBottom: '1rem' }}>
                        Enable MFA
                      </button>
                      <form className="form-grid" onSubmit={handleConfirmEnableMFA}>
                        <label>
                          Verification Code
                          <input type="text" value={mfaEnableCode} onChange={(e) => setMfaEnableCode(e.target.value)} placeholder="Enter code from above" maxLength={6} />
                        </label>
                        <button className="primary-button" type="submit" disabled={!mfaEnableCode}>Confirm Enable MFA</button>
                      </form>
                    </>
                  ) : (
                    <form className="form-grid" onSubmit={handleDisableMFA}>
                      <label>
                        Confirm Password to Disable
                        <PasswordField value={mfaDisablePassword} onChange={(e) => setMfaDisablePassword(e.target.value)} required placeholder="Your account password" />
                      </label>
                      <button className="danger-button" type="submit">Disable MFA</button>
                    </form>
                  )}
                </div>
              </section>
            )}

            {activeTab === 'admin' && user?.is_admin && (
              <section className="settings-section">
                <div className="panel">
                  <h2>Security Settings</h2>
                  <p className="muted-text">Configure password policies and security parameters for all users.</p>
                  {adminSettings && (
                    <form className="form-grid" onSubmit={handleUpdateAdminSettings}>
                      <label>
                        Min Password Length
                        <input type="number" min="6" max="128" value={adminSettings.min_password_length || ''} onChange={(e) => setAdminSettings((s) => ({ ...s, min_password_length: e.target.value }))} />
                      </label>
                      <label>
                        Require Uppercase
                        <select value={adminSettings.require_uppercase || 'true'} onChange={(e) => setAdminSettings((s) => ({ ...s, require_uppercase: e.target.value }))}>
                          <option value="true">Yes</option>
                          <option value="false">No</option>
                        </select>
                      </label>
                      <label>
                        Require Lowercase
                        <select value={adminSettings.require_lowercase || 'true'} onChange={(e) => setAdminSettings((s) => ({ ...s, require_lowercase: e.target.value }))}>
                          <option value="true">Yes</option>
                          <option value="false">No</option>
                        </select>
                      </label>
                      <label>
                        Require Digit
                        <select value={adminSettings.require_digit || 'true'} onChange={(e) => setAdminSettings((s) => ({ ...s, require_digit: e.target.value }))}>
                          <option value="true">Yes</option>
                          <option value="false">No</option>
                        </select>
                      </label>
                      <label>
                        Require Special Char
                        <select value={adminSettings.require_special_char || 'true'} onChange={(e) => setAdminSettings((s) => ({ ...s, require_special_char: e.target.value }))}>
                          <option value="true">Yes</option>
                          <option value="false">No</option>
                        </select>
                      </label>
                      <label>
                        Max Failed Attempts
                        <input type="number" min="0" max="100" value={adminSettings.max_failed_attempts || ''} onChange={(e) => setAdminSettings((s) => ({ ...s, max_failed_attempts: e.target.value }))} />
                      </label>
                      <label>
                        Lockout Duration
                        <input type="text" value={adminSettings.lockout_duration || ''} onChange={(e) => setAdminSettings((s) => ({ ...s, lockout_duration: e.target.value }))} placeholder="15m" />
                      </label>
                      <label>
                        Token Expiry
                        <input type="text" value={adminSettings.token_expiry || ''} onChange={(e) => setAdminSettings((s) => ({ ...s, token_expiry: e.target.value }))} placeholder="1h" />
                      </label>
                      <label>
                        Inactivity Timeout
                        <input type="text" value={adminSettings.inactivity_timeout || ''} onChange={(e) => setAdminSettings((s) => ({ ...s, inactivity_timeout: e.target.value }))} placeholder="15m" />
                      </label>
                      <button className="primary-button" type="submit">Save Settings</button>
                    </form>
                  )}
                </div>

                <div className="panel">
                  <h2>Users</h2>
                  <p className="muted-text">{adminUsers.length} registered user{adminUsers.length !== 1 ? 's' : ''}</p>
                  <div className="entry-list">
                    {adminUsers.map((u) => (
                      <div className="entry-card" key={u.id}>
                        <div className="entry-card-header">
                          <div>
                            <h3>{u.display_name || u.email}</h3>
                            <p className="muted-text">{u.email} {u.is_admin && '(Admin)'} {u.mfa_enabled && '(MFA)'}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default App;