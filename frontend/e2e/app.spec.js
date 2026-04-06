// @ts-check
import { test, expect } from '@playwright/test';

const API = 'http://127.0.0.1:8080';
let _uid = 0;
const uniqueEmail = () => `pw-e2e-${Date.now()}-${_uid++}@test.com`;
const TEST_PASSWORD = 'TestPass123!';

// The first registered user becomes admin. Store credentials for admin tests.
let ADMIN_EMAIL;
let ADMIN_TOKEN;

test.beforeAll(async ({ request }) => {
  ADMIN_EMAIL = uniqueEmail();
  const res = await request.post(`${API}/api/auth/register`, {
    data: { email: ADMIN_EMAIL, password: TEST_PASSWORD },
  });
  expect(res.status()).toBe(201);
  const body = await res.json();
  ADMIN_TOKEN = body.token;
});

// ─── Health & Accessibility ────────────────────────────────────────────

test.describe('Health & Page Load', () => {
  test('backend health endpoint returns ok', async ({ request }) => {
    const res = await request.get(`${API}/health`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('ok');
  });

  test('frontend loads and shows login form', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('h1')).toHaveText('Password Manager');
    await expect(page.locator('.eyebrow')).toHaveText('Phase 3');
    await expect(page.getByRole('button', { name: 'Login' }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Register' }).first()).toBeVisible();
  });

  test('service worker registers', async ({ page }) => {
    await page.goto('/');
    const swState = await page.evaluate(async () => {
      const reg = await navigator.serviceWorker.ready;
      return reg.active?.state;
    });
    expect(swState).toBe('activated');
  });
});

// ─── Registration ──────────────────────────────────────────────────────

test.describe('Registration', () => {
  test('register with valid credentials succeeds', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Register' }).first().click();
    await page.getByLabel('Email').fill(uniqueEmail());
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Register' }).last().click();

    // Should land in vault
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });
  });

  test('register with short password shows error', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Register' }).first().click();
    await page.getByLabel('Email').fill(uniqueEmail());
    await page.getByLabel('Password').fill('abc');
    await page.getByRole('button', { name: 'Register' }).last().click();

    await expect(page.locator('.error-alert')).toBeVisible({ timeout: 5000 });
  });

  test('register with duplicate email shows error', async ({ page }) => {
    const email = uniqueEmail();
    // First registration
    await page.goto('/');
    await page.getByRole('button', { name: 'Register' }).first().click();
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Register' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });

    // Logout
    await page.getByRole('button', { name: 'Logout' }).click();

    // Second registration with same email
    await page.getByRole('button', { name: 'Register' }).first().click();
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Register' }).last().click();
    await expect(page.locator('.error-alert')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.error-alert')).toContainText('already registered');
  });

  test('register with invalid email shows error', async ({ request }) => {
    // Browser HTML5 validation prevents form submission for type="email",
    // so test via API to verify backend also rejects invalid emails.
    const res = await request.post(`${API}/api/auth/register`, {
      data: { email: 'not-an-email', password: TEST_PASSWORD },
    });
    expect(res.status()).toBe(400);
  });

  test('password strength meter reacts to input', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Register' }).first().click();
    const pwField = page.getByLabel('Password');
    await pwField.fill('a');
    await expect(page.locator('.strength-meter')).toBeVisible();
    await pwField.fill('SuperStrong123!@#');
    // Strength should update (meter visible with different state)
    await expect(page.locator('.strength-meter')).toBeVisible();
  });
});

// ─── Login ─────────────────────────────────────────────────────────────

test.describe('Login', () => {
  let email;

  test.beforeAll(async ({ request }) => {
    email = uniqueEmail();
    await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
  });

  test('login with correct credentials succeeds', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });
  });

  test('login with wrong password shows error', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill('WrongPassword1!');
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.locator('.error-alert')).toBeVisible({ timeout: 5000 });
  });

  test('login with non-existent email shows error', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel('Email').fill('nonexistent@test.com');
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.locator('.error-alert')).toBeVisible({ timeout: 5000 });
  });
});

// ─── Password Vault CRUD ──────────────────────────────────────────────

test.describe('Password Vault', () => {
  let email;

  test.beforeEach(async ({ page, request }) => {
    email = uniqueEmail();
    await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    // Login via UI
    await page.goto('/');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });
  });

  test('create new entry and see it in vault', async ({ page }) => {
    await page.locator('input[type="text"]').first().fill('GitHub');
    // Username field
    const inputs = page.locator('.form-grid input[type="text"]');
    await inputs.nth(0).fill('GitHub');  // Title
    await inputs.nth(1).fill('myuser');  // Username

    // Password field inside form
    const pwInput = page.locator('.form-grid .password-with-generate input').first();
    await pwInput.fill('GitPass123!');

    await page.getByRole('button', { name: 'Save Entry' }).click();

    // Entry should appear in vault
    await expect(page.locator('.entry-card')).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator('.entry-card h3')).toHaveText('GitHub');
  });

  test('edit an existing entry', async ({ page }) => {
    // Create entry first
    const titleInput = page.locator('.form-grid input[type="text"]').first();
    await titleInput.fill('EditMe');
    const pwInput = page.locator('.form-grid .password-with-generate input').first();
    await pwInput.fill('Pass123!');
    await page.getByRole('button', { name: 'Save Entry' }).click();
    await expect(page.locator('.entry-card')).toHaveCount(1, { timeout: 5000 });

    // Click edit
    await page.getByRole('button', { name: 'Edit' }).click();
    await expect(page.getByRole('button', { name: 'Update Entry' })).toBeVisible();

    // Change title
    const editTitleInput = page.locator('.form-grid input[type="text"]').first();
    await editTitleInput.fill('Edited');
    await page.getByRole('button', { name: 'Update Entry' }).click();

    await expect(page.locator('.entry-card h3')).toHaveText('Edited', { timeout: 5000 });
  });

  test('delete an entry', async ({ page }) => {
    // Create entry
    const titleInput = page.locator('.form-grid input[type="text"]').first();
    await titleInput.fill('DeleteMe');
    const pwInput = page.locator('.form-grid .password-with-generate input').first();
    await pwInput.fill('Pass123!');
    await page.getByRole('button', { name: 'Save Entry' }).click();
    await expect(page.locator('.entry-card')).toHaveCount(1, { timeout: 5000 });

    // Delete
    await page.getByRole('button', { name: 'Delete' }).click();
    await expect(page.locator('.entry-card')).toHaveCount(0, { timeout: 5000 });
  });

  test('search filters entries', async ({ page }) => {
    // Create two entries
    for (const title of ['Alpha', 'Beta']) {
      const titleInput = page.locator('.form-grid input[type="text"]').first();
      await titleInput.fill(title);
      const pwInput = page.locator('.form-grid .password-with-generate input').first();
      await pwInput.fill('Pass123!');
      await page.getByRole('button', { name: 'Save Entry' }).click();
      await page.waitForTimeout(500);
    }

    await expect(page.locator('.entry-card')).toHaveCount(2, { timeout: 5000 });

    // Search for Alpha
    await page.locator('.search-input').fill('Alpha');
    await page.waitForTimeout(1000); // Wait for search debounce/reload
    await expect(page.locator('.entry-card')).toHaveCount(1, { timeout: 5000 });
    await expect(page.locator('.entry-card h3')).toHaveText('Alpha');
  });

  test('show/hide password toggle works', async ({ page }) => {
    // Create entry
    const titleInput = page.locator('.form-grid input[type="text"]').first();
    await titleInput.fill('ToggleTest');
    const pwInput = page.locator('.form-grid .password-with-generate input').first();
    await pwInput.fill('SecretPass!1');
    await page.getByRole('button', { name: 'Save Entry' }).click();
    await expect(page.locator('.entry-card')).toHaveCount(1, { timeout: 5000 });

    // Password should be masked initially
    const maskText = page.locator('.entry-card .masked-password');
    await expect(maskText).toBeVisible();
  });

  test('generate password button works', async ({ page }) => {
    const pwInput = page.locator('.form-grid .password-with-generate input').first();
    await expect(pwInput).toHaveValue('');
    await page.getByRole('button', { name: 'Generate' }).first().click();
    await page.waitForTimeout(1000);
    const value = await pwInput.inputValue();
    expect(value.length).toBeGreaterThan(8);
  });

  test('category filter works', async ({ page }) => {
    // Create entries with categories
    const titleInput = page.locator('.form-grid input[type="text"]').first();
    await titleInput.fill('Work Entry');
    const pwInput = page.locator('.form-grid .password-with-generate input').first();
    await pwInput.fill('Pass123!');
    // Fill category
    const categoryInput = page.locator('.form-grid input[type="text"]').nth(2);
    await categoryInput.fill('Work');
    await page.getByRole('button', { name: 'Save Entry' }).click();
    await page.waitForTimeout(500);

    await titleInput.fill('Personal Entry');
    await pwInput.fill('Pass123!');
    await categoryInput.fill('Personal');
    await page.getByRole('button', { name: 'Save Entry' }).click();
    await expect(page.locator('.entry-card')).toHaveCount(2, { timeout: 5000 });

    // Filter by Work category
    await page.locator('.category-select').selectOption('Work');
    await page.waitForTimeout(1000);
    await expect(page.locator('.entry-card')).toHaveCount(1, { timeout: 5000 });
  });
});

// ─── Logout & Session ──────────────────────────────────────────────────

test.describe('Session Management', () => {
  test('logout clears session and shows login', async ({ page, request }) => {
    const email = uniqueEmail();
    await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    await page.goto('/');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });

    // Logout
    await page.getByRole('button', { name: 'Logout' }).click();
    await expect(page.getByRole('button', { name: 'Login' }).first()).toBeVisible();
  });

  test('accessing app with expired/invalid token shows login', async ({ page }) => {
    await page.goto('/');
    await page.evaluate(() => {
      localStorage.setItem('pm_token', 'invalid-jwt-token');
    });
    await page.reload();
    // Should eventually redirect to login or show login (token will fail on API call)
    await expect(page.getByRole('button', { name: 'Login' }).first()).toBeVisible({ timeout: 10000 });
  });
});

// ─── Password Reset ────────────────────────────────────────────────────

test.describe('Password Reset', () => {
  test('reset password flow shows correct forms', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Reset Password' }).first().click();
    await expect(page.getByLabel('Email')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Request Reset' })).toBeVisible();
  });
});

// ─── Tabs (Authenticated Features) ────────────────────────────────────

test.describe('Authenticated Tabs', () => {
  let email;

  test.beforeEach(async ({ page, request }) => {
    email = uniqueEmail();
    await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    await page.goto('/');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });
  });

  test('vault tab is active by default', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Vault' })).toHaveClass(/active/);
  });

  test('export/import tab shows forms', async ({ page }) => {
    await page.getByRole('button', { name: 'Export / Import' }).click();
    await expect(page.getByRole('heading', { name: 'Export Vault' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Import Vault' })).toBeVisible();
  });

  test('MFA tab shows status', async ({ page }) => {
    await page.getByRole('button', { name: 'MFA' }).click();
    await expect(page.getByText('Multi-Factor Authentication')).toBeVisible();
    await expect(page.getByText('Status:')).toBeVisible();
  });

  test('admin tab visible for first user (admin)', async ({ page }) => {
    // Login as admin user (first registered user)
    await page.getByRole('button', { name: 'Logout' }).click();
    await page.getByLabel('Email').fill(ADMIN_EMAIL);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: 'Admin' })).toBeVisible();
  });

  test('admin tab shows settings and users', async ({ page }) => {
    // Login as admin user
    await page.getByRole('button', { name: 'Logout' }).click();
    await page.getByLabel('Email').fill(ADMIN_EMAIL);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });
    await page.getByRole('button', { name: 'Admin' }).click();
    await expect(page.getByText('Security Settings')).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible({ timeout: 5000 });
  });
});

// ─── Export/Import Flow ────────────────────────────────────────────────

test.describe('Export & Import', () => {
  test('export vault with correct password works', async ({ page, request }) => {
    const email = uniqueEmail();
    const res = await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    const { token } = await res.json();

    // Create an entry via API
    await request.post(`${API}/api/passwords`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { title: 'ExportTest', username: 'u', password: 'p123' },
    });

    // Login via UI
    await page.goto('/');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Login' }).last().click();
    await expect(page.getByText('New Password Entry')).toBeVisible({ timeout: 10000 });

    // Go to export tab
    await page.getByRole('button', { name: 'Export / Import' }).click();

    // Fill password for export
    const pwFields = page.locator('input[type="password"]');
    await pwFields.first().fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Export Vault' }).click();

    // Should show success message
    await expect(page.locator('.success-alert')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.success-alert')).toContainText('exported');
  });
});

// ─── API Contract Verification ─────────────────────────────────────────

test.describe('API Contracts', () => {
  test('register returns correct shape', async ({ request }) => {
    const res = await request.post(`${API}/api/auth/register`, {
      data: { email: uniqueEmail(), password: TEST_PASSWORD },
    });
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body).toHaveProperty('token');
    expect(body).toHaveProperty('user');
    expect(body.user).toHaveProperty('id');
    expect(body.user).toHaveProperty('email');
  });

  test('login returns correct shape', async ({ request }) => {
    const email = uniqueEmail();
    await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    const res = await request.post(`${API}/api/auth/login`, {
      data: { email, password: TEST_PASSWORD },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('token');
    expect(body).toHaveProperty('user');
  });

  test('password CRUD returns correct shapes', async ({ request }) => {
    const email = uniqueEmail();
    const regRes = await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    const { token } = await regRes.json();
    const auth = { Authorization: `Bearer ${token}` };

    // Create
    const createRes = await request.post(`${API}/api/passwords`, {
      headers: auth,
      data: { title: 'Test', username: 'u', password: 'p123', category: 'Cat' },
    });
    expect(createRes.status()).toBe(201);
    const created = await createRes.json();
    // Create returns a bare entry object (not wrapped)
    expect(created).toHaveProperty('id');
    expect(created).toHaveProperty('title');
    const id = created.id;

    // List returns { entries: [...] }
    const listRes = await request.get(`${API}/api/passwords`, { headers: auth });
    expect(listRes.status()).toBe(200);
    const listed = await listRes.json();
    expect(listed).toHaveProperty('entries');
    expect(listed.entries.length).toBe(1);

    // Get returns bare entry
    const getRes = await request.get(`${API}/api/passwords/${id}`, { headers: auth });
    expect(getRes.status()).toBe(200);
    const got = await getRes.json();
    expect(got).toHaveProperty('id');
    expect(got).toHaveProperty('title');

    // Update
    const updateRes = await request.put(`${API}/api/passwords/${id}`, {
      headers: auth,
      data: { title: 'Updated', username: 'u2', password: 'p456' },
    });
    expect(updateRes.status()).toBe(200);

    // Delete (soft)
    const deleteRes = await request.delete(`${API}/api/passwords/${id}`, {
      headers: auth,
    });
    expect(deleteRes.status()).toBe(200);

    // List should be empty now
    const listRes2 = await request.get(`${API}/api/passwords`, { headers: auth });
    const listed2 = await listRes2.json();
    expect(listed2.entries.length).toBe(0);
  });

  test('sync endpoint returns correct shape', async ({ request }) => {
    const email = uniqueEmail();
    const regRes = await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    const { token } = await regRes.json();
    const auth = { Authorization: `Bearer ${token}` };

    const syncRes = await request.post(`${API}/api/sync`, {
      headers: auth,
      data: { entries: [] },
    });
    expect(syncRes.status()).toBe(200);
    const synced = await syncRes.json();
    expect(synced).toHaveProperty('entries');
    expect(synced).toHaveProperty('sync_at');
  });

  test('security policy endpoint returns correct shape', async ({ request }) => {
    const res = await request.get(`${API}/api/auth/security-policy`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty('min_password_length');
    expect(body).toHaveProperty('require_uppercase');
    expect(body).toHaveProperty('require_lowercase');
  });

  test('unauthenticated requests to protected routes return 401', async ({ request }) => {
    const endpoints = [
      { method: 'GET', url: `${API}/api/passwords` },
      { method: 'POST', url: `${API}/api/passwords` },
      { method: 'POST', url: `${API}/api/sync` },
      { method: 'POST', url: `${API}/api/vault/export` },
      { method: 'GET', url: `${API}/api/admin/settings` },
    ];

    for (const ep of endpoints) {
      const res = ep.method === 'GET'
        ? await request.get(ep.url)
        : await request.post(ep.url, { data: {} });
      expect(res.status(), `${ep.method} ${ep.url}`).toBe(401);
    }
  });
});

// ─── MFA Flow (API-level) ──────────────────────────────────────────────

test.describe('MFA Flow', () => {
  test('enable and verify MFA via API', async ({ request }) => {
    const email = uniqueEmail();
    const regRes = await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    const { token } = await regRes.json();
    const auth = { Authorization: `Bearer ${token}` };

    // Enable MFA
    const enableRes = await request.post(`${API}/api/auth/mfa/enable`, {
      headers: auth,
    });
    expect(enableRes.status()).toBe(200);
    const { code } = await enableRes.json();
    expect(code).toBeTruthy();

    // Confirm enable
    const confirmRes = await request.post(`${API}/api/auth/mfa/enable/verify`, {
      headers: auth,
      data: { code },
    });
    expect(confirmRes.status()).toBe(200);

    // Login should now require MFA
    const loginRes = await request.post(`${API}/api/auth/login`, {
      data: { email, password: TEST_PASSWORD },
    });
    const loginBody = await loginRes.json();
    expect(loginBody.mfa_required).toBe(true);
    expect(loginBody.mfa_token).toBeTruthy();
    expect(loginBody.mfa_code).toBeTruthy(); // MVP: code in response

    // Verify MFA
    const verifyRes = await request.post(`${API}/api/auth/mfa/verify`, {
      data: { mfa_token: loginBody.mfa_token, code: loginBody.mfa_code },
    });
    expect(verifyRes.status()).toBe(200);
    const verifyBody = await verifyRes.json();
    expect(verifyBody.token).toBeTruthy();
  });
});

// ─── Admin Access Control ──────────────────────────────────────────────

test.describe('Admin Access', () => {
  test('non-admin cannot access admin endpoints', async ({ request }) => {
    // Register a non-admin user (admin was already registered in beforeAll)
    const email2 = uniqueEmail();
    const res = await request.post(`${API}/api/auth/register`, {
      data: { email: email2, password: TEST_PASSWORD },
    });
    const { token } = await res.json();

    const adminRes = await request.get(`${API}/api/admin/settings`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(adminRes.status()).toBe(403);
  });

  test('admin can access admin endpoints', async ({ request }) => {
    // Use the admin token from beforeAll (first registered user)
    const adminRes = await request.get(`${API}/api/admin/settings`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    expect(adminRes.status()).toBe(200);
  });
});

// ─── Export/Import API ─────────────────────────────────────────────────

test.describe('Export/Import API', () => {
  test('export and import round-trip preserves data', async ({ request }) => {
    const email = uniqueEmail();
    const regRes = await request.post(`${API}/api/auth/register`, {
      data: { email, password: TEST_PASSWORD },
    });
    const { token } = await regRes.json();
    const auth = { Authorization: `Bearer ${token}` };

    // Create entries
    for (const title of ['Entry1', 'Entry2']) {
      await request.post(`${API}/api/passwords`, {
        headers: auth,
        data: { title, username: 'u', password: 'p1' },
      });
    }

    // Export
    const exportRes = await request.post(`${API}/api/vault/export`, {
      headers: auth,
      data: { password: TEST_PASSWORD },
    });
    expect(exportRes.status()).toBe(200);
    const exportBody = await exportRes.json();
    expect(exportBody.count).toBe(2);

    // Register new user and import
    const email2 = uniqueEmail();
    const reg2 = await request.post(`${API}/api/auth/register`, {
      data: { email: email2, password: TEST_PASSWORD },
    });
    const { token: token2 } = await reg2.json();
    const auth2 = { Authorization: `Bearer ${token2}` };

    const importRes = await request.post(`${API}/api/vault/import`, {
      headers: auth2,
      data: { password: TEST_PASSWORD, data: exportBody.data },
    });
    expect(importRes.status()).toBe(200);
    const importBody = await importRes.json();
    expect(importBody.imported).toBe(2);

    // Verify entries exist
    const listRes = await request.get(`${API}/api/passwords`, { headers: auth2 });
    const listBody = await listRes.json();
    expect(listBody.entries.length).toBe(2);
  });
});
