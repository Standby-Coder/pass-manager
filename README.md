# Password Manager using Go

## Stack Summary

- **Frontend:** React
- **Backend:** Go with Gin
- **ORM:** GORM
- **Database:** SQLite using the GORM SQLite driver

## Roadmap: Password Manager with React + Go + SQLite

### Phase 1: Project Setup & Core MVP
#### Objectives

- Establish basic infrastructure.
- Implement secure user signup/login.
- Build a basic password vault CRUD flow with secure storage foundations.

#### Tasks

- [x] Set up React frontend project.

- [x] Set up Go backend project with Gin.

- [x] Design SQLite database schema for users and password entries.

- [x] Configure GORM with the SQLite driver.

- [x] Implement user registration with password hashing.

- [x] Implement login with JWT-based authentication.

- [x] Build API endpoints for CRUD operations on password entries.

- [x] Define secure handling for sensitive password fields in the backend.

- [x] Create React UI to add/view/delete password entries.

- [x] Implement basic client-server communication.

- [x] Test end-to-end user signup, login, and password entry management.

### Phase 2: Security Hardening & UX Enhancements
#### Objectives

- Strengthen security around data handling and authentication.
- Improve frontend experience.

#### Tasks

- [x] Enable configurable registration security like password length, complexity, and max failed logon attempts and locking accounts based on it

- [x] Implement client-side protection for sensitive credential workflows where appropriate.

- [x] Add password strength meter on the frontend.

- [x] Implement a lightweight strong password generator satisfying the configured security settings

- [x] Secure API routes with proper Gin authentication middleware.

- [x] Implement logout on inactivity and token expiration.

- [x] Implement password reset flow.

- [x] Sanitize and validate all user inputs.

- [x] Add search and filter capabilities in the password vault UI.

- [x] Implement a secure show/hide password toggle.

- [x] Write unit tests for backend authentication and data protection modules.

- [x] Check for all security issues and solve all issues.

### Phase 3: Syncing & Backup
#### Objectives

- [x] Enable secure multi-device syncing.

- [x] Implement secure backup/export/import.

- [x] Use viper package (and other packages from spf13) for the application

- [x] Make sure the sqlite db is encrypted so that no one can open the database using the sqlite3 command.

- [x] Add a flag which decrypts the entire sqlite db into a json format.

- [x] Make sure the saved/stored passwords are encrypted, so that even if they decrypted using external methods other than the flag cannot make sense of it. Only if the decrypt flag (created as per the previous point) is used, the password should be visible.

- [x] Run another round of sanity test/integration test with all the requirements to be fulfilled, verified and completed

#### Tasks

- [x] Make this a portable web app such that it can be accessed offline with limited access such as getting passwords for last 10 added entries for only one user.

- [x] Make an instance admin account which is the only account which sets all configurable parameters.

- [x] Create secure sync API endpoints supporting protected data payloads.

- [x] Implement client-side caching or local persistence for offline-friendly access, if possible.

- [x] Build vault export/import functionality.

- [x] Design and implement conflict resolution for syncing.

- [x] Implement email multi-factor authentication support.

- [x] Add integration tests covering sync and MFA flows.

- [x] Allow secure export/import of a user's password bank using the user's password as the password to decrypt the zip of json files. This relates to the vault export/import functionality.

### Phase 4: Advanced Features & Production Readiness
#### Objectives

- Add advanced usability and security features.
- Prepare for production deployment.

#### Tasks

- [ ] Use stronger encryption to store passwords and if possinle use MSYM/random nonce IV keys to encrypt. 

- [ ] Add biometric login support on compatible devices.

- [ ] Add password breach-checking capability if included in scope.

- [ ] Add secure notes and file attachments support.

- [ ] Build shared vaults with role-based access control.

- [ ] Harden the Go backend with rate limiting, account lockout, and audit logging.

- [ ] Perform security testing and vulnerability assessments.

- [ ] Optimize frontend UI responsiveness and accessibility.

- [ ] Set up build, test, and deployment workflows.

- [ ] Write comprehensive documentation and user guides.