# Good-to-Have Features

Enhancements that would improve UX, security posture, and maintainability.

---

## User Experience

### 1. Dark/Light Mode Toggle
- Currently always dark theme. Add a toggle switch with system preference detection via `prefers-color-scheme`.

### 2. Keyboard Shortcuts
- Common actions: `Ctrl+N` new entry, `Ctrl+S` save, `Ctrl+F` focus search, `Escape` cancel edit.

### 3. Undo Delete
- Currently entries are permanently deleted (soft delete exists in DB but no undo UI). Add a "Deleted" section or an undo toast notification with a 10-second window.

### 4. Bulk Operations
- Select multiple entries → bulk delete, bulk export, bulk re-categorize.

### 5. Sorting Options
- Sort vault by title (A–Z), date created, date modified, category.

### 6. Copy to Clipboard
- One-click copy for username and password fields. Auto-clear clipboard after 30 seconds.

### 7. Password History
- Track previous passwords for each entry. Useful for sites that don't accept recently used passwords.

### 8. Favicon/Logo Fetching
- Auto-fetch site favicons for entry cards using the stored URL.

### 9. Entry Notes with Markdown
- Support basic markdown rendering in the notes field.

### 10. Mobile-Responsive Improvements
- Current layout works on mobile but could be improved with a bottom navigation bar and swipe gestures.

---

## Security Enhancements

### 11. Password Breach Checking
- Integrate with HaveIBeenPwned API (k-anonymity model) to warn users if their passwords appear in known breaches.

### 12. TOTP Authenticator MFA
- Support time-based OTP via apps like Google Authenticator, Authy, or 1Password, in addition to email codes.

### 13. MFA Backup Codes
- Generate 8–10 one-time backup codes when MFA is enabled. Users can recover access if they lose their MFA device.

### 14. Key Rotation Mechanism
- Allow rotating the field encryption key with re-encryption of all stored passwords.

### 15. Session Management Dashboard
- List active sessions (device, IP, last active). Allow revoking individual sessions.

### 16. Two-Person Integrity for Admin
- Require a second admin approval for critical actions (delete all entries, disable MFA for a user).

---

## Technical Improvements

### 17. Request Retry with Exponential Backoff
- Frontend API calls should retry on network errors (1s, 2s, 4s) before showing an error.

### 18. React Component Splitting
- Break the monolithic `App.jsx` (~900 lines) into smaller components: `AuthForms`, `VaultView`, `AdminPanel`, `MFASettings`, `ExportImport`.

### 19. WebSocket for Real-Time Sync
- Replace polling-based sync with WebSocket or Server-Sent Events for instant cross-device updates.

### 20. Browser Extension
- Chrome/Firefox extension for auto-fill and quick password lookup without opening the web app.

### 21. Database Backup/Restore
- Automated periodic JSON backup of the vault. One-click restore from backup.

### 22. API Documentation
- Add Swagger/OpenAPI documentation for all endpoints.

---

## Accessibility

### 23. Focus-Visible Indicators
- Add `:focus-visible` outlines on all interactive elements for keyboard navigation.

### 24. Screen Reader Support
- Add `aria-label` to icon buttons, `aria-live` regions for dynamic content, and proper heading hierarchy.

### 25. Reduced Motion Support
- Respect `prefers-reduced-motion` media query for animations and transitions.

### 26. High Contrast Mode
- Support `prefers-contrast: more` with higher contrast colors and thicker borders.
