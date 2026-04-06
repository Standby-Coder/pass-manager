# Security Issues

Security audit findings for the pass-manager application.

---

## High Severity

### 1. No Security Response Headers ✅ FIXED
- **File:** `backend/internal/middleware/auth.go`
- **Fix applied:** Added `SecurityHeaders()` middleware with `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 0`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`. Wired into router before CORS.

### 2. No Rate Limiting ⚠️ OPEN
- **Problem:** No request rate limiting on any endpoint. Auth endpoints vulnerable to brute-force.
- **Note:** Requires adding a rate-limiting library (e.g., `golang.org/x/time/rate` or `gin-contrib/limiter`). Deferred — account lockout mitigates single-account brute-force.

### 3. MFA Code Returned in API Response ⚠️ OPEN (by design)
- **Problem:** MFA code is returned directly in the login API response. This is an intentional MVP shortcut (no email service configured).
- **Note:** Requires email/SMS delivery service to fix properly.

### 4. JWT Token Stored in localStorage ⚠️ OPEN
- **Problem:** JWT accessible to any JavaScript on the page.
- **Note:** Requires httpOnly cookie refactor across backend + frontend. CSP meta tag added to mitigate XSS risk.

### 5. No HTTPS Enforcement ⚠️ OPEN
- **Problem:** No TLS configuration. Deployment concern, not a code-level fix.
- **Note:** Should be deployed behind a reverse proxy (nginx, Caddy) with TLS termination.

---

## Medium Severity

### 6. No Token Revocation Mechanism ⚠️ OPEN
- **Problem:** JWT tokens cannot be revoked once issued. Logout is client-side only.
- **Note:** Would require a JWT blacklist table or switch to refresh token pattern.

### 7. Default JWT Secret ✅ FIXED
- **File:** `backend/internal/config/config.go`
- **Fix applied:** Added `WarnInsecureDefaults()` method that logs a warning when JWT_SECRET is the default value. Called on server startup.

### 8. No Content Security Policy in Frontend ✅ FIXED
- **File:** `frontend/index.html`
- **Fix applied:** Added CSP meta tag: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:8080 ws://127.0.0.1:5173; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'`

### 9. Service Worker Cache Key Hardcoded ⚠️ OPEN
- **Problem:** Cache key `pass-manager-v1` never changes. Requires build-time cache busting.
- **Note:** Best addressed with Vite build-time cache busting and Workbox integration.

---

## Low Severity

### 10. Missing Vary: Origin Header ✅ FIXED
- **File:** `backend/internal/middleware/auth.go` (CORS middleware)
- **Fix applied:** Added `Vary: Origin` header when `Access-Control-Allow-Origin` is set.

### 11. No Subresource Integrity ⚠️ OPEN
- **Problem:** No SRI hashes on script/style tags. Not currently using CDN resources.
- **Note:** Would be relevant if external CDN resources are added.
