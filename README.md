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

- [ ] Set up React frontend project.

- [ ] Set up Go backend project with Gin.

- [ ] Design SQLite database schema for users and password entries.

- [ ] Configure GORM with the SQLite driver.

- [ ] Implement user registration with password hashing.

- [ ] Implement login with JWT-based authentication.

- [ ] Build API endpoints for CRUD operations on password entries.

- [ ] Define secure handling for sensitive password fields in the backend.

- [ ] Create React UI to add/view/delete password entries.

- [ ] Implement basic client-server communication.

- [ ] Test end-to-end user signup, login, and password entry management.

### Phase 2: Security Hardening & UX Enhancements
#### Objectives

- Strengthen security around data handling and authentication.
- Improve frontend experience.

#### Tasks

- [ ] Implement client-side protection for sensitive credential workflows where appropriate.

- [ ] Add password strength meter and password generator on the frontend.

- [ ] Secure API routes with proper Gin authentication middleware.

- [ ] Implement logout on inactivity and token expiration.

- [ ] Implement password reset flow.

- [ ] Sanitize and validate all user inputs.

- [ ] Add search and filter capabilities in the password vault UI.

- [ ] Implement a secure show/hide password toggle.

- [ ] Write unit tests for backend authentication and data protection modules.

### Phase 3: Syncing & Backup
#### Objectives

- Enable secure multi-device syncing.
- Implement secure backup/export/import.

#### Tasks

- [ ] Create secure sync API endpoints supporting protected data payloads.

- [ ] Implement client-side caching or local persistence for offline-friendly access.

- [ ] Build vault export/import functionality.

- [ ] Design and implement conflict resolution for syncing.

- [ ] Implement multi-factor authentication support.

- [ ] Add integration tests covering sync and MFA flows.

### Phase 4: Advanced Features & Production Readiness
#### Objectives

- Add advanced usability and security features.
- Prepare for production deployment.

#### Tasks

- [ ] Add biometric login support on compatible devices.

- [ ] Add password breach-checking capability if included in scope.

- [ ] Add secure notes and file attachments support.

- [ ] Build shared vaults with role-based access control.

- [ ] Harden the Go backend with rate limiting, account lockout, and audit logging.

- [ ] Perform security testing and vulnerability assessments.

- [ ] Optimize frontend UI responsiveness and accessibility.

- [ ] Set up build, test, and deployment workflows.

- [ ] Write comprehensive documentation and user guides.