# Bugs

Confirmed bugs found during comprehensive code audit and E2E testing.

---

## Critical

### 1. MFA Code Generation — Operator Precedence Bug ✅ FIXED
- **File:** `backend/internal/models/user.go` line 83
- **Fix applied:** `(int(b[0])<<16|int(b[1])<<8|int(b[2])) % 1000000`
- Removed the now-unnecessary `code[:6]` truncation.

### 2. Ignored Encryptor Initialization Error ✅ FIXED
- **File:** `backend/internal/router/router.go` line 18
- **Fix applied:** `enc, err := crypto.NewFieldEncryptor(cfg.EncryptionKey); if err != nil { log.Fatalf(...) }`

---

## High

### 3. Silent Decrypt Error in Vault Export ✅ FIXED
- **File:** `backend/internal/handlers/export.go` line 92
- **Fix applied:** Returns HTTP 500 error with entry title on decryption failure instead of exporting blank password.

### 4. Frontend Entry Normalization Bug ✅ FIXED (previous session)
- **Status:** Fixed by removing `data?.password` fallback.

---

## Medium

### 5. rand.Read Error Ignored in Sync ✅ FIXED
- **File:** `backend/internal/handlers/sync.go`
- **Fix applied:** `generateClientID()` now returns `(string, error)` and callers handle the error.

### 6. Service Worker Undefined Fallback ✅ FIXED
- **File:** `frontend/public/sw.js` line 40
- **Fix applied:** `.catch(() => cached || new Response('Offline', { status: 503, statusText: 'Service Unavailable' }))`

### 7. Stale Closure in Inactivity Timer ✅ FIXED
- **File:** `frontend/src/App.jsx`
- **Fix applied:** `handleLogout` converted to `useCallback` and moved before `resetInactivityTimer`. Added to dependency array.

---

## Low

### 8. Missing useEffect Dependency ✅ FIXED
- **File:** `frontend/src/App.jsx`
- **Fix applied:** Added `isAuthenticated` to search/filter useEffect dependency array.

### 9. javascript: URL Possible in Entry Links ✅ FIXED
- **File:** `frontend/src/App.jsx`
- **Fix applied:** URL scheme validated against `http:` and `https:` before rendering as `<a href>`. Non-matching schemes shown as plain text.
