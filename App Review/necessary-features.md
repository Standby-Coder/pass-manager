# Necessary Features

Features that should be implemented before any production deployment.

---

## Security (Required)

### 1. HTTPS / TLS Support
- All data currently transmitted in plaintext. Passwords, tokens, MFA codes visible to any network observer.
- Either add TLS support to the Go server or mandate reverse proxy (nginx/caddy) with TLS.

### 2. Rate Limiting
- Auth endpoints vulnerable to brute-force and credential stuffing.
- Add per-IP rate limiting: 10 req/min on `/login`, `/register`, `/password-reset/request`.

### 3. Security Response Headers
- Add `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`.

### 4. Secure Token Storage
- Move JWT from localStorage to httpOnly secure cookies, or implement refresh token rotation.

### 5. Proper MFA Implementation
- Remove MFA code from API response. Use actual email delivery or TOTP (Google Authenticator).

### 6. JWT Secret Validation
- Refuse to start if JWT_SECRET is the default `"change-me"` value.

---

## Reliability (Required)

### 7. Error Handling in Critical Paths
- Fix silent decrypt error in export (`export.go` line 92).
- Fix ignored encryptor initialization error (`router.go` line 18).
- Handle `rand.Read` error in sync client ID generation.

### 8. MFA Code Generation Fix
- Fix operator precedence bug in `user.go` line 83 to ensure uniform 6-digit code distribution.

### 9. React Error Boundary
- No error boundary in the React app. An uncaught render error crashes the entire UI with a blank page.
- Add `<ErrorBoundary>` wrapper around the app.

### 10. Graceful Shutdown
- No signal handling (SIGTERM/SIGINT). On crash or forced stop, DB encryption-at-rest may not run.
- Add `os.Signal` handling to ensure `EncryptOnShutdown()` is called.

---

## Data Integrity (Required)

### 11. Search Debouncing
- Every keystroke fires an API call. This is both a performance and UX issue — results flicker and can show stale data.

### 12. Pagination
- Vault list loads ALL entries. Will break with large vaults (memory, render time, network).

### 13. Database Migrations
- Relying solely on GORM AutoMigrate. No versioned migration system. Schema changes in production could silently drop data.

---

## Operational (Required)

### 14. Structured Logging
- No structured or leveled logging. Debug messages mixed with errors. No request logging middleware beyond Gin defaults.

### 15. Audit Logging
- No log of login attempts, password changes, exports, admin actions. Required for security compliance.

### 16. Health Check Enhancement
- Current `/health` only checks DB connectivity. Should also check encryption key validity, disk space, and service dependencies.
