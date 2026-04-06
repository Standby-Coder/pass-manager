# Memory Snapshot — /memories/repo/pass-manager.md

> This is a complete copy of the memory file recorded at `/memories/repo/pass-manager.md` at the time of this audit.

---

# Password Manager — Project Context

## Status
- **Phase 1: COMPLETE** (all 11 tasks done and verified)
- **Phase 2: COMPLETE** (all 12 tasks done and verified)
- **Phase 3: COMPLETE** (all 7 objectives + 9 tasks done and verified)
- Branch: `Go`

## Stack
- Frontend: React 18 + Vite (port 5173), PWA with service worker
- Backend: Go + Gin (port 8080), Cobra CLI, Viper config
- ORM: GORM
- DB: SQLite (`data/pass-manager.db`), file-level AES-256-GCM encryption at rest
- Auth: bcrypt password hashing + HS256 JWT (configurable expiry)
- Encryption: AES-256-GCM field encryption (passwords), Argon2id key derivation
- Config: Viper (config.yaml + env vars), Cobra CLI (serve/decrypt commands)

## Project Structure
```
backend/
  cmd/server/main.go          — entrypoint, loads config → DB → router → serve
  internal/
    config/config.go           — env-based config (APP_HOST, APP_PORT, DATABASE_PATH, JWT_SECRET)
    database/database.go       — GORM+SQLite init, AutoMigrate
    models/
      user.go                  — User model (bcrypt SetPassword/CheckPassword, PasswordHash json:"-")
      password_entry.go        — PasswordEntry model (Title, Username, Password, URL, Notes, Category)
    handlers/
      auth.go                  — Register + Login handlers, JWT generation, errorJSON helper
      passwords.go             — List/Create/Get/Update/Delete + findOwnedEntry (scoped by user_id)
      health.go                — DB health check
      auth_test.go             — 3 tests (register, validation/conflict, login success/failure)
      passwords_test.go        — 3 tests (auth required, CRUD+scoping, validation paths)
    middleware/auth.go         — CORS() middleware + JWTAuth() middleware + UserIDFromContext()
    router/router.go           — Route wiring: /health, /api/auth/*, /api/passwords/* (JWT-protected)
frontend/
  src/
    api.js                     — fetch wrapper with Bearer token, register/login/CRUD exports
    App.jsx                    — Single-page app: auth tabs (login/register) + vault (create/list/delete)
    main.jsx                   — React root
    styles.css                 — Dark theme UI
```

## API Endpoints
- `GET  /health` — DB health check
- `POST /api/auth/register` — {email, password, display_name} → {user, token}
- `POST /api/auth/login` — {email, password} → {user, token}
- `POST /api/auth/password-reset/request` — {email} → {message, reset_token}
- `POST /api/auth/password-reset/confirm` — {token, new_password} → {message}
- `GET  /api/auth/security-policy` — security config (min length, complexity, timeouts)
- `POST /api/auth/generate-password` — {length?} → {password}
- `GET  /api/passwords` — list entries (JWT required, supports ?search=&category=)
- `POST /api/passwords` — create entry (JWT required)
- `GET  /api/passwords/:id` — get entry (JWT required, user-scoped)
- `PUT  /api/passwords/:id` — update entry (JWT required, user-scoped)
- `DELETE /api/passwords/:id` — delete entry (JWT required, user-scoped)

## Run Commands
- Backend: `cd backend && go run ./cmd/server/`
- Frontend: `cd frontend && npm run dev`
- Backend tests: `cd backend && go test ./... -v`
- Frontend build: `cd frontend && npm run build`

## Key Design Decisions
- PasswordHash uses `json:"-"` so it's never exposed in API responses
- Auth responses use a `userResponse` DTO (not raw model)
- Password entries scoped by user_id via `findOwnedEntry()` — users can only access their own data
- CORS restricted to configured `ALLOWED_ORIGINS` (default: http://127.0.0.1:5173)
- JWT secret defaults to "change-me" — must be set via JWT_SECRET env var in production
- Security config via env vars: MIN_PASSWORD_LENGTH, REQUIRE_UPPERCASE/LOWERCASE/DIGIT/SPECIAL_CHAR, MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION, TOKEN_EXPIRY, INACTIVITY_TIMEOUT
- Account lockout after N failed login attempts, auto-unlocks after duration
- Password reset via token flow (token stored hashed, 1h expiry)
- Inactivity logout on frontend via user activity listeners
- All inputs sanitized (null byte removal, length limits)
- Password generator uses crypto/rand for secure randomness

## Phase 2 Features Added
- Configurable password complexity (min length, uppercase, lowercase, digit, special char)
- Account lockout on failed login attempts with configurable threshold and duration
- Password reset flow (request token → confirm with new password)
- Password generator endpoint (crypto/rand, Fisher-Yates shuffle)
- Password strength meter (frontend, uses policy from backend)
- Show/hide password toggle on all password fields and vault entries
- Search and filter (search by title/username/url/notes/category + category dropdown)
- Inactivity logout (configurable timeout, resets on user interaction)
- Input validation with length limits matching DB schema
- Input sanitization (null byte removal)
- CORS restricted to allowed origins
- Token expiry reduced from 24h to 1h (configurable)
- Email format validation with regex
- 15 backend unit tests covering: register, validation, login, password strength, lockout, reset flow, password generator, security policy, email validation, search/filter, input length

## Phase 2 Test Results (all pass)
- 15 Go unit tests total (up from 6)
- TestAuthHandlerRegisterSuccess, TestAuthHandlerRegisterValidationAndConflict, TestAuthHandlerLoginSuccessAndFailure
- TestPasswordValidation, TestAccountLockout, TestPasswordResetFlow, TestGeneratePassword, TestSecurityPolicy, TestEmailValidation, TestPasswordResetNonExistentEmail
- TestPasswordHandlerAuthRequired, TestPasswordHandlerCRUDAndScoping, TestPasswordHandlerValidationPaths, TestPasswordHandlerSearchFilter, TestPasswordHandlerInputLengthValidation

## Phase 3 Features Added
- Viper config management (config.yaml + backward-compatible env vars)
- Cobra CLI with `serve` (default) and `decrypt` subcommands
- AES-256-GCM field-level password encryption (`enc:` prefix, random nonce per call)
- AES-256-GCM database file encryption at rest (auto-decrypt on start, encrypt on shutdown)
- Argon2id key derivation from passphrases
- `./pass-manager decrypt --output file.json` decrypts DB + password fields to JSON
- Instance admin account (first registered user, or via ADMIN_EMAIL config)
- Admin panel: GET/PUT /api/admin/settings, GET /api/admin/users (AdminRequired middleware)
- Email MFA: enable/confirm/disable/verify flow (6-digit codes, 5min expiry)
- Vault export: encrypted with user's password (AES-GCM via crypto.EncryptData)
- Vault import: decrypts with user's password, imports entries
- Sync API: POST /api/sync with bidirectional push/pull, last-write-wins conflict resolution
- Soft delete for sync compatibility (IsDeleted flag, SyncVersion counter)
- PWA: manifest.json, service worker (stale-while-revalidate), offline detection
- Client-side caching: last 10 entries in localStorage for offline access
- Frontend tabs: Vault, Export/Import, MFA Settings, Admin (admin-only)

## Phase 3 New API Endpoints
- `POST /api/auth/mfa/verify` — {mfa_token, code} → {user, token}
- `POST /api/auth/mfa/enable` — generate MFA code (JWT required)
- `POST /api/auth/mfa/enable/verify` — {code} → confirm MFA enable (JWT required)
- `POST /api/auth/mfa/disable` — {password} → disable MFA (JWT required)
- `POST /api/sync` — {last_sync_at?, entries} → {entries, sync_at, conflicts}
- `POST /api/vault/export` — {password} → {data, count} (JWT required)
- `POST /api/vault/import` — {password, data} → {imported, total} (JWT required)
- `GET  /api/admin/settings` — security config (JWT + Admin required)
- `PUT  /api/admin/settings` — update security config (JWT + Admin required)
- `GET  /api/admin/users` — list all users (JWT + Admin required)

## Phase 3 New Files
- `internal/crypto/crypto.go` — FieldEncryptor, EncryptFile/DecryptFile, EncryptData/DecryptData, DeriveKey
- `internal/crypto/crypto_test.go` — 10 crypto tests
- `internal/models/app_setting.go` — AppSetting model (key/value admin settings)
- `internal/handlers/admin.go` — GetSettings, UpdateSettings, ListUsers
- `internal/handlers/sync.go` — Sync handler (push/pull/conflict resolution)
- `internal/handlers/export.go` — Export/Import handler
- `internal/handlers/integration_test.go` — 5 integration tests (MFA, export/import, admin, sync, encryption)
- `frontend/public/manifest.json` — PWA manifest
- `frontend/public/sw.js` — Service worker

## Phase 3 Test Results (all pass)
- 30 Go tests total (up from 15)
- 10 crypto tests: nil passthrough, round-trip, different nonces, empty plaintext, wrong key, file encryption round-trip, file wrong key, data encryption round-trip, data wrong password
- 5 integration tests: MFAEnableDisableFlow, ExportImportFlow, AdminSettingsAndAccess, SyncPushAndPull, PasswordFieldEncryptionInHandler
- 15 original handler tests still passing
