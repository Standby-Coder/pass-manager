# Performance Issues

Performance bottlenecks and optimization opportunities.

---

## High Impact

### 1. No Search Debouncing
- **File:** `frontend/src/App.jsx` lines 238–240
- **Problem:** Every keystroke in the search box triggers an immediate API call via `useEffect`. Typing a 20-character search produces 20 HTTP requests.
- **Impact:** Excessive backend load, poor UX with flickering results, unnecessary network traffic.
- **Fix:** Add a 300–500ms debounce before triggering `loadEntries()`.

### 2. No Pagination for Password Entries
- **Files:** `backend/internal/handlers/passwords.go` (List handler), `frontend/src/App.jsx`
- **Problem:** `List` handler fetches ALL entries for the user with no pagination. As the vault grows (hundreds/thousands of entries), response payload and rendering time increase linearly.
- **Impact:** Slow page loads, high memory usage for large vaults.
- **Fix:** Add `?page=&limit=` query parameters with default limit of 50.

---

## Medium Impact

### 3. Security Config Queried on Every Request
- **File:** `backend/internal/handlers/auth.go` (`securityConfig` function)
- **Problem:** `securityConfig()` queries multiple `AppSetting` rows from the database on every call. This is invoked on login, register, password validation, and security policy requests.
- **Impact:** Unnecessary DB queries for config that rarely changes.
- **Fix:** Cache security config in memory with a TTL (e.g., 5 minutes) or invalidate on admin settings update.

### 4. Sync Decrypts All Passwords
- **File:** `backend/internal/handlers/sync.go` (pull phase)
- **Problem:** The sync pull phase decrypts every password entry for the user, even if the client already has the latest version. No delta/incremental sync based on `last_sync_at`.
- **Impact:** O(n) decrypt operations per sync call, wasteful for periodic background syncs.
- **Fix:** Only return entries with `updated_at > last_sync_at`.

### 5. Sync N+1 DB Queries (Push Phase)
- **File:** `backend/internal/handlers/sync.go` (push phase)
- **Problem:** For each client entry in the push phase, a separate DB query checks for existing entries by `client_id`. For N entries, that's N queries.
- **Impact:** Slow sync for large batches.
- **Fix:** Batch-fetch existing entries by client_id in a single query.

### 6. Export Loads Entire Vault Into Memory
- **File:** `backend/internal/handlers/export.go`
- **Problem:** Export fetches all entries, decrypts all passwords, marshals to JSON, encrypts the blob — all in memory. No streaming or chunking.
- **Impact:** For vaults with thousands of entries, this consumes significant memory.

---

## Low Impact

### 7. No Database Indexing Beyond GORM Defaults
- **File:** `backend/internal/models/password_entry.go`
- **Problem:** No explicit indexes on frequently queried columns like `user_id + is_deleted`, `client_id`, `updated_at`, or `category`. GORM only creates primary key indexes by default.
- **Fix:** Add composite indexes for common query patterns.

### 8. Frontend Re-renders on All State Changes
- **File:** `frontend/src/App.jsx`
- **Problem:** The entire App component is a single component with many state variables. Any state change re-renders the whole tree.
- **Impact:** Minor for current app size but will degrade with more features.
- **Fix:** Split into smaller components with proper state colocation.
