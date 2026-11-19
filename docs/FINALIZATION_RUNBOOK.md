# Finalization report — browser identity, tenant isolation and recovery

**Date:** 19 November 2026

**Branch:** feat/multi-user-auth-production-recovery

**Scope:** local implementation and verification of browser authentication, workspace isolation, production-oriented HTTPS Compose configuration and workspace-set recovery.

## Executive result

The core browser login and multi-user workspace isolation have been implemented. The UI now has a custom responsive sign-in / first-admin setup experience and a workspace administration panel. Server-side sessions and roles are enforced on every API request, and each workspace has a separate SQLite evidence database. A Caddy HTTPS deployment profile and multi-workspace backup/restore tooling are also included.

**This is not a claim of a fully deployed or independently certified public production service.** The local Docker engine is unavailable, and no domain, VPS/host, external secret store, monitoring provider or independent penetration tester was supplied. The production stack is authored and Compose-validated but has not been started on a public host.

## Browser authentication and workspace isolation

- First registration bootstraps the first workspace administrator. Non-loopback startup requires a unique ASCII `CLOUDSHIELD_BOOTSTRAP_TOKEN` of at least 32 characters, and first signup must present it.
- Later accounts require a single-use, 24-hour invitation.
- Admins can invite analyst and responder members, create isolated workspaces with a new admin invitation, view team members and disable member accounts.
- Passwords are salted scrypt hashes; minimum 12 characters.
- Opaque session tokens are stored as SHA-256 hashes; 12-hour absolute expiry; logout and member disable revoke sessions.
- Cookies are HttpOnly, SameSite=Strict; production requires Secure cookies.
- State-changing requests require a CSRF cookie/header match and Origin validation.
- Login attempts are rate-limited by the TCP peer address; forwarded headers are not trusted. Behind the single Caddy ingress this conservatively applies the limiter to the proxy peer. Eight failed password attempts lock the account for 15 minutes. Login password/email input lengths are bounded before database/scrypt work.
- Auth events are written to a central auth audit table.
- Tenant IDs are selected only from the authenticated server-side session. Each tenant gets a distinct SQLite file. Cross-tenant API access is tested.
- Shared AWS/Azure credentials and collector routes are blocked in multi-user mode until per-tenant cloud identities exist.
- The legacy loopback-only local mode remains the default unless multi-user mode is explicitly enabled.

## Visual work

- New branded sign-in / registration screen with responsive two-column layout, product value proposition, security assurances and inline error handling.
- First-admin and invitation registration flows.
- Workspace team modal with member roles, one-time invitation creation, separate workspace creation and member revocation.
- Signed-in user display, team navigation and sign-out control.
- Responsive mobile layout and session-expiry return to sign-in.
- Vite production build passes.

## Production deployment profile

- Added compose.production.yaml with Caddy as the only public ingress on 80/443.
- Python API is not published to the host. Caddy reaches it over a private internal backend network. The API has a separate outbound identity-egress bridge for Firebase token verification; host egress policy must restrict this to required Google Auth/certificate endpoints.
- Caddy configuration provides automatic HTTPS, HSTS and security headers.
- App container retains non-root execution, read-only root filesystem, dropped capabilities, no-new-privileges and persistent /data volume.
- Production environment enables multi-user auth and Secure cookies; a unique first-admin bootstrap key is required and passed only to the app container, never to Caddy. Sample secrets/config are not embedded in the image or committed as .env.production.
- .dockerignore excludes deployment environment files and backups.
- Cloud collection flags are off; shared server credentials are blocked in multi-user mode.

## Workspace backup and recovery

New CLI:
- cloudshield backup-workspaces
- cloudshield verify-workspaces
- cloudshield restore-workspaces

The archive contains the auth database and every tenant database. It includes an internal manifest and a sidecar SHA-256 manifest. Verification checks archive digest, file list, bounded archive sizes, per-database digest and SQLite integrity. Restore rejects unsafe paths, verifies restored databases, removes partial restores on failure and refuses to overwrite an existing destination. Archive members are restricted to the exact auth database and 64-hex tenant database naming scheme; Windows drive-qualified paths, backslashes and unexpected members are rejected before extraction.

Windows Docker scripts:
- `scripts/deploy-production.ps1` — guarded config/build/start and internal plus external HTTPS health checks.
- `scripts/backup-production.ps1` — stops app writes, runs a one-off backup container, verifies/copies the archive and manifest, then restarts the app in a finally block.
- `scripts/recovery-drill.ps1` — verifies and restores to a fresh isolated path and checks database integrity.

Automated end-to-end recovery test:
1. Create an auth database and workspace.
2. Create and ingest synthetic evidence in the workspace database.
3. Create a multi-workspace backup.
4. Verify the archive.
5. Restore into a new directory.
6. Authenticate using the restored session.
7. Verify the restored tenant evidence count and SQLite integrity.

This exercise passes in the local Python test environment. It is not a substitute for a scheduled recovery drill on the actual production host using independent off-host media.

## Validation snapshot

| Check | Result |
|---|---|
| Python unit/integration suite | 138 tests passed locally |
| Auth + recovery module statement coverage | 96% locally (auth 99%, recovery 92%); CI enforces at least 90% |
| Full-run repository coverage | 91% branch-inclusive aggregate across instrumented source and test modules; this includes test modules and is not a source-only package metric. |
| CI coverage gate | Enforces at least 90% statement coverage on authentication and workspace recovery modules. |
| Python compileall | Passed |
| Detection evaluation | 30/30 curated fixtures; not production accuracy |
| Bandit source scan | Zero findings |
| pip-audit | No known vulnerabilities in pinned `requirements-cloud.lock` (AWS/Azure/signing runtime dependencies) |
| npm audit --omit=dev | 0 vulnerabilities |
| Vite production build | Passed |
| Terraform fmt | Passed |
| Terraform secure validate | Passed |
| Terraform vulnerable-fixture validate | Passed |
| Local and production Compose config | Parsed successfully; production topology assertions passed (no app host port, internal backend, bootstrap secret isolated to app) |
| PowerShell deployment/backup/restore scripts | Parsed successfully |
| Local Docker engine | Not available on this workstation; Docker Desktop/Engine is not installed, so no local image run or container recovery drill was possible. |
| Public production deployment | Not performed: no approved host/domain, DNS/firewall, or deployment owner was supplied. |

| Live AWS/Azure calls | Not run |

The dependency audit was run against the project's pinned `requirements-cloud.lock` (no known vulnerabilities). A separate audit of the global Windows Python environment reported unrelated packages outside this repository and is not treated as a CloudShield dependency finding.

## Open release gates — do not represent as complete

1. **Enterprise identity:** MFA/WebAuthn, OIDC/SAML SSO, verified email, self-service password reset and device/session management UI are not implemented.
2. **Independent security assurance:** penetration test and independent tenant-isolation review are required before public launch.
3. **Real production deployment:** supply an approved host, DNS domain, firewall policy and deployment owner; configure the private .env.production file and run the Caddy stack. Compose configuration and network/secret-isolation assertions pass, and the earlier GitHub Actions container build passed, but this workstation has no Docker Engine and no public host was supplied, so the production stack has not been started or exercised end to end.
4. **Operations:** configure central monitoring/alerting, external append-only audit export, secret manager, automated encrypted off-host backup and incident-response ownership.
5. **Production recovery:** run the supplied backup/recovery scripts against the actual host and independently stored backup media; record RPO/RTO.
6. **Cloud providers:** tenant-specific AWS/Azure identity onboarding, permissions and validation remain disabled until that design exists. Do not reuse a global cloud credential across workspaces.
7. **Evidence custody:** SHA-256 sidecar manifests are not a trust anchor if stored with the archive. Sign/store manifests independently and integrate TSA/WORM if required.

## First-use setup

Local multi-user mode:

    $env:CLOUDSHIELD_AUTH_MODE = "multi_user"
    $env:CLOUDSHIELD_COOKIE_SECURE = "0"
    python -m cloudshield.api

Open http://127.0.0.1:8765 and create the first administrator. For production, use compose.production.yaml with a real domain and .env.production; never use HTTP or disable Secure cookies on a non-loopback bind.

## Final disposition

**Core local engineering is delivered. Public production launch remains gated by actual infrastructure, enterprise identity, independent review and operational ownership.** Keep the service local-only until those gates have been completed and signed off.


## Addendum — Firebase Authentication integration (19 November 2026)

A separate feature branch feat/firebase-auth-integration adds an optional Firebase identity provider without moving workspace data out of SQLite.

- Firebase Web SDK email/password signup and login, email verification, and password-reset email are integrated into the branded sign-in screen.
- Python Firebase Admin SDK verifies ID tokens and checks revocation before issuing CloudShield's own 12-hour HttpOnly session.
- Firebase UID mapping is unique; roles, invitation authorization, audit, and workspace boundaries remain local.
- Legacy password login/registration endpoints are disabled whenever Firebase provider mode is selected.
- Existing local accounts are never auto-linked by email; explicit migration is required.
- Production Compose mounts the Admin SDK JSON as a read-only secret; public Web SDK settings are supplied through environment variables.
- Added Firebase identity unit/API tests, a deployment guide at docs/FIREBASE_AUTH.md, and a dated validation report at docs/FIREBASE_AUTH_REPORT.md.
- MFA and enterprise SAML/OIDC are not enabled; these require Identity Platform features and a separate cost/security approval.

**External setup blocker:** Firebase project cloudshield-ae534 has an active CloudShield Web app and a secured local Admin SDK key, but Firebase Authentication itself is not initialized. A read-only Identity Toolkit probe and a scoped configuration update both returned CONFIGURATION_NOT_FOUND. In Firebase Console, open Build → Authentication → Get started, enable Email/Password, and save. No paid plan or billing change was made. The UI explains this state rather than claiming sign-in works.

This addendum supersedes the earlier report's statement that email verification and password recovery were wholly unimplemented; the application flows are now implemented but cannot be live-tested until the Firebase Console prerequisite is completed.
