# Test Results

Complete test results from comprehensive retesting session.

---

## Backend Go Tests — 30/30 PASS

```
go test ./... -v -count=1
```

### Crypto Tests (10)
| # | Test | Status |
|---|------|--------|
| 1 | TestFieldEncryptorNilPassthrough | PASS |
| 2 | TestFieldEncryptorRoundTrip | PASS |
| 3 | TestFieldEncryptorDifferentNonces | PASS |
| 4 | TestFieldEncryptorEmptyPlaintext | PASS |
| 5 | TestFieldEncryptorWrongKey | PASS |
| 6 | TestFileEncryptionRoundTrip | PASS |
| 7 | TestFileDecryptionWrongKey | PASS |
| 8 | TestDataEncryptionRoundTrip | PASS |
| 9 | TestDataDecryptionWrongPassword | PASS |
| 10 | (TestFieldEncryptorPrefix — included in RoundTrip) | — |

### Auth Handler Tests (10)
| # | Test | Status |
|---|------|--------|
| 1 | TestAuthHandlerRegisterSuccess | PASS |
| 2 | TestAuthHandlerRegisterValidationAndConflict | PASS |
| 3 | TestAuthHandlerLoginSuccessAndFailure | PASS |
| 4 | TestPasswordValidation | PASS |
| 5 | TestAccountLockout | PASS |
| 6 | TestPasswordResetFlow | PASS |
| 7 | TestGeneratePassword | PASS |
| 8 | TestSecurityPolicy | PASS |
| 9 | TestEmailValidation | PASS |
| 10 | TestPasswordResetNonExistentEmail | PASS |

### Password Handler Tests (5)
| # | Test | Status |
|---|------|--------|
| 1 | TestPasswordHandlerAuthRequired | PASS |
| 2 | TestPasswordHandlerCRUDAndScoping | PASS |
| 3 | TestPasswordHandlerValidationPaths | PASS |
| 4 | TestPasswordHandlerSearchFilter | PASS |
| 5 | TestPasswordHandlerInputLengthValidation | PASS |

### Integration Tests (5)
| # | Test | Status |
|---|------|--------|
| 1 | TestMFAEnableDisableFlow | PASS |
| 2 | TestExportImportFlow | PASS |
| 3 | TestAdminSettingsAndAccess | PASS |
| 4 | TestSyncPushAndPull | PASS |
| 5 | TestPasswordFieldEncryptionInHandler | PASS |

---

## Playwright E2E Tests — 37/37 PASS

```
npx playwright test --reporter=line
```

Configuration: Chromium headless, 1 worker, 30s timeout, base URL http://127.0.0.1:5173

### Health & Page Load (3)
| # | Test | Status |
|---|------|--------|
| 1 | backend health endpoint returns ok | PASS |
| 2 | frontend loads and shows login form | PASS |
| 3 | service worker registers | PASS |

### Registration (5)
| # | Test | Status |
|---|------|--------|
| 4 | register with valid credentials succeeds | PASS |
| 5 | register with short password shows error | PASS |
| 6 | register with duplicate email shows error | PASS |
| 7 | register with invalid email shows error (API-level) | PASS |
| 8 | password strength meter reacts to input | PASS |

### Login (3)
| # | Test | Status |
|---|------|--------|
| 9 | login with correct credentials succeeds | PASS |
| 10 | login with wrong password shows error | PASS |
| 11 | login with non-existent email shows error | PASS |

### Password Vault CRUD (7)
| # | Test | Status |
|---|------|--------|
| 12 | create new entry and see it in vault | PASS |
| 13 | edit an existing entry | PASS |
| 14 | delete an entry | PASS |
| 15 | search filters entries | PASS |
| 16 | show/hide password toggle works | PASS |
| 17 | generate password button works | PASS |
| 18 | category filter works | PASS |

### Session Management (2)
| # | Test | Status |
|---|------|--------|
| 19 | logout clears session and shows login | PASS |
| 20 | accessing app with invalid token shows login | PASS |

### Password Reset (1)
| # | Test | Status |
|---|------|--------|
| 21 | reset password flow shows correct forms | PASS |

### Authenticated Tabs (5)
| # | Test | Status |
|---|------|--------|
| 22 | vault tab is active by default | PASS |
| 23 | export/import tab shows forms | PASS |
| 24 | MFA tab shows status | PASS |
| 25 | admin tab visible for first user (admin) | PASS |
| 26 | admin tab shows settings and users | PASS |

### Export & Import (1)
| # | Test | Status |
|---|------|--------|
| 27 | export vault with correct password works | PASS |

### API Contracts (6)
| # | Test | Status |
|---|------|--------|
| 28 | register returns correct shape | PASS |
| 29 | login returns correct shape | PASS |
| 30 | password CRUD returns correct shapes | PASS |
| 31 | sync endpoint returns correct shape | PASS |
| 32 | security policy endpoint returns correct shape | PASS |
| 33 | unauthenticated requests to protected routes return 401 | PASS |

### MFA Flow (1)
| # | Test | Status |
|---|------|--------|
| 34 | enable and verify MFA via API | PASS |

### Admin Access Control (2)
| # | Test | Status |
|---|------|--------|
| 35 | non-admin cannot access admin endpoints | PASS |
| 36 | admin can access admin endpoints | PASS |

### Export/Import API (1)
| # | Test | Status |
|---|------|--------|
| 37 | export and import round-trip preserves data | PASS |

---

## Bugs Found & Fixed During Testing

### 1. Frontend Entry Normalization Bug (FIXED)
- **File:** `frontend/src/App.jsx`
- **Problem:** `data?.entry || data?.password || data` — the `?.password` fallback matched the entry's password string field from bare Create/Update responses, causing entries to be stored as strings instead of objects. Vault entries rendered with empty titles.
- **Fix:** Changed to `data?.entry || data` (removed `data?.password` fallback).

### 2. E2E Test Selector Bugs (FIXED)
- `.strength-bar` selector → changed to `.strength-meter` (correct CSS class)
- `.form-grid input[type="text"]` nth(3) → nth(2) for category (URL is `type="url"`)
- `getByText('Export Vault')` → `getByRole('heading')` (strict mode violation: matched both h2 and button)
- `getByText('Users')` → `getByRole('heading', { name: 'Users' })` (strict mode: matched subtitle text too)
- MFA confirm endpoint: `/api/auth/mfa/enable/confirm` → `/api/auth/mfa/enable/verify` (route mismatch)
- Admin tests: fixed to use first-registered admin user credentials instead of per-test registration
- Invalid email test: changed to API-level test (browser HTML5 validation prevents form submission)
