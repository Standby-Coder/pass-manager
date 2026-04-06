# Design Workflows

Current user flows and improvement suggestions.

---

## Current Flows

### 1. Registration Flow
```
User opens app → Sees login form → Clicks "Register" tab
→ Fills email + password (+ optional display name)
→ Password strength meter shows feedback
→ Clicks "Register" → API POST /api/auth/register
→ On success: receives JWT, redirected to vault
→ On failure: error message shown (duplicate email, weak password)
```
**Notes:** First registered user automatically becomes admin. No email verification.

### 2. Login Flow
```
User opens app → Fills email + password → Clicks "Login"
→ API POST /api/auth/login
→ If MFA enabled: redirect to MFA verify form
  → User enters 6-digit code → API POST /api/auth/mfa/verify
→ On success: JWT stored in localStorage, vault loaded
→ On failure: error message (wrong password, account locked)
```
**Account lockout:** After N failed attempts (configurable), account is locked for a duration.

### 3. Vault CRUD Flow
```
Authenticated user sees two-panel layout:
  Left: New/Edit entry form (Title, Username, Password, URL, Category, Notes)
  Right: Vault list with search + category filter

Create: Fill form → Click "Save Entry" → API POST /api/passwords → Entry appears in list
Edit:   Click "Edit" on card → Form populates → Modify → Click "Update Entry" → API PUT
Delete: Click "Delete" on card → API DELETE → Entry removed from list
Search: Type in search box → API filters by title/username/url/notes/category
Filter: Select category dropdown → API filters by category
```

### 4. MFA Setup Flow
```
User clicks "MFA" tab → Sees MFA status (Enabled/Disabled)
→ Clicks "Enable MFA" → API POST /api/auth/mfa/enable
→ Receives 6-digit code (MVP: shown in UI, should be emailed)
→ Enters code in confirm form → API POST /api/auth/mfa/enable/verify
→ On success: MFA is enabled, future logins require code
→ To disable: enters current password → API POST /api/auth/mfa/disable
```

### 5. Export/Import Flow
```
Export:
  User clicks "Export / Import" tab
  → Enters account password in "Confirm Password" field
  → Clicks "Export Vault" → API POST /api/vault/export
  → Server decrypts all passwords → encrypts with user's password (AES-GCM)
  → Browser downloads encrypted .enc file

Import:
  User enters password + uploads .enc file (or pastes encrypted data)
  → Clicks "Import" → API POST /api/vault/import
  → Server decrypts with provided password → imports entries
  → Success message shows count
```

### 6. Admin Flow
```
Admin user sees "Admin" tab (only visible if user.is_admin === true)
→ Clicks "Admin" → Loads security settings + user list

Security Settings panel:
  - Min Password Length, Require Uppercase/Lowercase/Digit/Special
  - Max Failed Attempts, Lockout Duration, Token Expiry, Inactivity Timeout
  → Modify values → Click "Save Settings" → API PUT /api/admin/settings

Users panel:
  - List of all registered users (email, display name, admin status, MFA status)
  - Read-only in current implementation
```

### 7. Password Reset Flow
```
User clicks "Reset Password" tab
→ Enters email → Clicks "Request Reset"
→ API returns reset token (MVP: shown in response, should be emailed)
→ User enters token + new password → Clicks "Reset Password"
→ API POST /api/auth/password-reset/confirm
→ On success: redirected to login with new password
```

### 8. Offline Flow
```
User goes offline → "Offline Mode" badge appears
→ Last 10 cached entries shown from localStorage
→ Entry form disabled (read-only mode)
→ User comes back online → badge disappears
→ User can refresh to reload live data
```

### 9. Inactivity Logout Flow
```
User is authenticated → Activity timer starts (configurable, default 15min)
→ User activity (mouse, keyboard, scroll, touch) resets timer
→ No activity for timeout duration → automatic logout
→ Token cleared, redirected to login with "Logged out due to inactivity" message
```

---

## Suggested Workflow Improvements

### A. Email Verification on Registration
```
Register → Email sent with verification link → User clicks link
→ Account activated → Can now login
```
Prevents fake account creation and verifies email ownership for password reset.

### B. Onboarding Tutorial
```
First login → Welcome modal with key features overview
→ Step-by-step: Create first entry → Show password toggle → Explain MFA
→ Dismiss to start using vault
```

### C. Quick Search with Keyboard
```
Ctrl+K or / → Focus search bar → Type → Results filter in real-time
→ Arrow keys to navigate results → Enter to select → Auto-copy password
```

### D. Import from Other Managers
```
Export/Import tab → "Import from..." dropdown
→ Options: CSV (generic), LastPass CSV, 1Password CSV, Bitwarden JSON
→ Upload file → Map columns → Preview entries → Confirm import
```

### E. Entry Sharing
```
Click "Share" on entry → Generate encrypted sharing link with expiry
→ Recipient opens link → Enters decryption password → Views entry once
→ Link auto-expires after view or time limit
```

### F. Vault Health Report
```
Admin/User clicks "Vault Health" → Analysis runs:
  - Weak passwords (strength < Good)
  - Reused passwords across entries
  - Old passwords (> 90 days unchanged)
  - Missing MFA recommendation
  - Breach-checking results
→ Shows score with actionable fix suggestions
```
