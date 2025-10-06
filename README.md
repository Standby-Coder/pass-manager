# pass-manager
Password Manager

## Roadmap: Password Manager with React.js + Rust + MySQL
### Phase 1: Project Setup & Core MVP
#### Objectives

- Establish basic infrastructure.
- Implement secure user signup/login.
- Basic password vault CRUD with encryption.

#### Tasks

- [ ] Set up React frontend project (e.g., Vite or Create React App).

- [ ] Set up Rust backend project with chosen framework (Actix-web or Rocket).

- [ ] Design MySQL database schema for users and password entries.

- [ ] Implement user registration with password hashing (Argon2 recommended).

- [ ] Implement login with JWT-based authentication.

- [ ] Build API endpoints for CRUD operations on password entries.

- [ ] Encrypt password fields server-side using a key derived from master password.

- [ ] Create React UI to add/view/delete password entries.

- [ ] Implement basic client-server communication over HTTPS.

- [ ] Test end-to-end user signup, login, and password entry management.

### Phase 2: Security Hardening & UX Enhancements
#### Objectives

- Strengthen security around encryption and auth.
- Improve frontend experience.

#### Tasks

- [ ] Implement client-side encryption/decryption of passwords using WebCrypto API.

- [ ] Add password strength meter and password generator on frontend.

- [ ] Secure API routes with proper authentication middleware.

- [ ] Implement logout on inactivity & token expiration.

- [ ] Implement password reset flow with secure email verification.

- [ ] Sanitize and validate all user inputs (prevent XSS, SQL injection).

- [ ] Add search and filter capabilities in password vault UI.

- [ ] Implement “show/hide password” toggle securely.

- [ ] Write unit tests for backend authentication and encryption modules.

### Phase 3: Syncing & Backup
#### Objectives

- Enable secure multi-device syncing.
- Implement secure backup/export/import.

#### Tasks

- [ ] Create secure sync API endpoints supporting encrypted data blobs.

- [ ] Implement client-side caching (IndexedDB or secure local storage).

- [ ] Build encrypted vault export/import functionality.

- [ ] Design and implement conflict resolution for syncing.

- [ ] Implement multi-factor authentication (MFA) with TOTP or email.

- [ ] Add integration tests covering sync and MFA flows.

### Phase 4: Advanced Features & Production Readiness
#### Objectives

- Add advanced usability and security features.
- Prepare for production deployment.

Tasks

- [ ] Add biometric login support on compatible devices (e.g., WebAuthn). (need to check)

- [ ] Integrate breach detection APIs (e.g., HaveIBeenPwned) for passwords.

- [ ] Add secure notes and file attachments with encryption.

- [ ] Build shared vaults with role-based access control (optional)

- [ ] Harden backend with rate limiting, account lockout, and audit logging.

- [ ] Perform penetration testing and vulnerability assessments.

- [ ] Optimize frontend UI responsiveness and accessibility.

- [ ] Set up CI/CD pipelines for build, test, and deployment.

- [ ] Write comprehensive documentation and user guides.
