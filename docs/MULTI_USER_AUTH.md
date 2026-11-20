# Multi-user browser authentication and workspace isolation

## Delivered behavior

Set `CLOUDSHIELD_AUTH_MODE=multi_user` to enable browser authentication. The legacy loopback-only mode remains the default for existing local users.

- The first registered account becomes the initial workspace administrator. On non-loopback deployments, startup requires a unique `CLOUDSHIELD_BOOTSTRAP_TOKEN` of at least 32 characters and the first signup must supply it; this prevents an internet visitor from racing to claim the first admin account. Keep the token in the protected deployment environment file. Once the first admin is created, registration remains invitation-only.
- Later accounts can register only with a single-use, 24-hour invitation.
- Administrators can invite analysts (read-only) and responders (incident workflow, ingestion and simulation).
- Administrators can create a separate workspace and issue its first administrator a one-time invitation.
- Administrators can revoke a member; revocation disables the account and deletes its active sessions.
- The legacy local password provider stores salted scrypt hashes, never plaintext; minimum length is 12 characters. The optional Firebase provider delegates password storage, email verification and password recovery to Firebase Authentication.
- Login attempts are rate-limited by the TCP peer address; forwarded headers are not trusted because they can be forged unless a verified proxy trust chain is configured. Behind the single Caddy ingress this conservatively applies the limiter to the proxy peer. Eight consecutive failures lock an account for 15 minutes.
- Browser sessions are random opaque tokens; only SHA-256 token hashes are stored. Sessions expire after 12 hours and are revoked on logout or member disable.
- Session cookies are HttpOnly, SameSite=Strict; the separate CSRF cookie is checked against a matching request header and its server-side hash.
- In HTTPS production mode set `CLOUDSHIELD_COOKIE_SECURE=1`; startup refuses a non-loopback bind if secure cookies are not enabled.
- Every workspace uses a separate SQLite evidence database. The tenant identifier is derived from the authenticated server-side session, never accepted from a request parameter.
- The central authentication database stores users, tenant memberships, invitation hashes, sessions and authentication audit events. Firebase mode also stores a unique Firebase UID per user; role and workspace authorization remain local and server-controlled.
- Shared AWS/Azure server credentials are deliberately unavailable in multi-user mode. Provider collection endpoints are blocked until per-tenant cloud identities and authorization scopes are implemented.

## Start locally for the first time

PowerShell:

```powershell
$env:CLOUDSHIELD_AUTH_MODE = "multi_user"
$env:CLOUDSHIELD_AUTH_DB = "$PWD\artifacts\auth.sqlite3"
$env:CLOUDSHIELD_TENANT_DIR = "$PWD\artifacts\tenants"
$env:CLOUDSHIELD_COOKIE_SECURE = "0" # local loopback HTTP only
python -m cloudshield.api
```

Open `http://127.0.0.1:8765`. The first account created through the registration screen becomes workspace admin. Choose a strong, unique passphrase. Do not reuse the example credentials in automated tests.

## Invite and isolate a second workspace

1. Sign in as the workspace administrator.
2. Open **Team** in the top bar.
3. Use **Invite to this workspace** to issue an analyst or responder invitation.
4. Use **Create an isolated workspace** to create another workspace and a one-time administrator invitation.
5. Share the invitation through a private channel. It is a bearer credential; anyone who receives it can claim it once before expiry.
6. The invitee opens the sign-in screen, switches to **Create account**, enters the invitation code and creates their own account.
7. Each workspace is stored in a different database file under `CLOUDSHIELD_TENANT_DIR`. There is no cross-workspace search or implicit membership.

The account model intentionally assigns one account to one workspace. To access another workspace, use a separate account and invitation. Cross-workspace membership and switching are not implemented.

## Role boundaries

| Capability | Analyst | Responder | Admin |
|---|---:|---:|---:|
| Read dashboard, events, findings, incidents and evidence | Yes | Yes | Yes |
| Verify portable evidence bundles | Yes | Yes | Yes |
| Ingest telemetry and run synthetic scenarios | No | Yes | Yes |
| Update incident workflow and add notes | No | Yes | Yes |
| Invoke cloud collection | No | No | No in shared mode |
| Invite members / create workspace | No | No | Yes |
| Disable workspace member | No | No | Yes |

Role checks are enforced in the server, not only in the UI.

## Production configuration

The production Compose stack is separate from the existing local-only Compose profile:

- `compose.production.yaml` runs the app on a private Docker network without publishing its API port.
- Caddy is the only public ingress and terminates HTTPS for the configured domain.
- Set `CLOUDSHIELD_DOMAIN` and `CLOUDSHIELD_TLS_EMAIL` in the deployment host's private `.env.production` file.
- Copy `.env.production.example` to `.env.production`; set a real domain/email and generate `CLOUDSHIELD_BOOTSTRAP_TOKEN` with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Protect the file with host filesystem ACLs and never commit it.
- Ensure DNS A/AAAA records point to the host and allow inbound TCP 80/443 (and UDP 443 if HTTP/3 is desired).
- Production Compose sets multi-user auth and Secure cookies. The API container is not published directly.
- Cloud collection flags remain off; provider credentials must not be shared across tenants.
- Caddy certificates and app data live in persistent named volumes.

Commands on a Linux deployment host (after editing the private environment file and setting the bootstrap key):

```sh
cp .env.production.example .env.production
# Edit the domain and TLS email; keep file permissions restricted.
chmod 600 .env.production
docker compose --env-file .env.production -f compose.production.yaml config --quiet
docker compose --env-file .env.production -f compose.production.yaml up --build -d
docker compose --env-file .env.production -f compose.production.yaml ps
docker compose --env-file .env.production -f compose.production.yaml logs --tail=100 caddy cloudshield
```

The sample domain is a placeholder. Do not start the public ingress until real DNS, firewall rules, private environment values, and a host backup plan are in place.

## Firebase identity provider

Set CLOUDSHIELD_AUTH_PROVIDER=firebase to use Firebase Authentication for browser identity. Firebase email/password registration, verified-email enforcement, password reset and backend ID-token verification are integrated. The Firebase UID maps to the existing CloudShield user record; tenant isolation, role checks, invitation use and session cookies remain enforced by CloudShield. Firebase mode disables the legacy password login and registration routes.

The Firebase Console Authentication product must first be initialized and the Email/Password provider enabled. Configure the public Web app values and read-only Admin SDK secret in the production environment. See [FIREBASE_AUTH.md](FIREBASE_AUTH.md) for the setup procedure, exact environment variables, migration behavior, and current project status.

Existing local accounts are not silently linked by email. A Firebase identity that matches an existing unlinked local email is rejected pending an explicit migration. Advanced MFA and enterprise SAML/OIDC are not part of the Spark-plan integration and remain separate release gates.

## Workspace-set backup and restore

The single-database backup commands remain available for local use. Multi-user deployments must back up the authentication database and every tenant database as one workspace set.

The Windows backup script now stops the CloudShield application, runs the archive operation in a one-off container against the persistent volume, verifies the archive, copies the archive and sidecar to the host, and restarts the application in a `finally` block. This creates a consistent cross-database snapshot at the cost of a short maintenance window. Review service health after restart. Then copy both files to independent protected storage.

Manual operators must stop the app process before creating the workspace-set archive. Do not back up auth and tenant files while writes are active.

```sh
cloudshield backup-workspaces \
  --auth-database /data/auth.sqlite3 \
  --tenant-directory /data/tenants \
  --output /data/backups/cloudshield-workspaces.zip

cloudshield verify-workspaces /data/backups/cloudshield-workspaces.zip

cloudshield restore-workspaces /data/backups/cloudshield-workspaces.zip \
  --destination /data/recovery-drill/restored
```

The archive contains an internal file manifest and a colocated SHA-256 sidecar. Verification checks the outer archive digest, exact archive member list, every database digest and each SQLite integrity result. Restore refuses an existing destination, rejects unsafe archive paths and re-verifies restored databases. The sidecar is not an independent trust anchor if both files can be modified; copy/sign it in separate protected storage.

Windows operators can use `scripts/backup-production.ps1` and `scripts/recovery-drill.ps1` with Docker Compose.

## Security limitations — do not overstate readiness

This is a first-party password/session system, not a complete enterprise identity platform. The following remain unimplemented and are required before a high-assurance public SaaS launch:

- OIDC/SAML SSO, MFA/WebAuthn, recovery codes and device/session management UI.
- Existing-account linking/migration workflow and invitation email delivery.
- Session listing, device management and admin-driven session revocation UI (member disable revokes all that member's sessions).
- Centralized distributed rate limiting and external audit log export.
- Per-tenant AWS/Azure identity onboarding, credential rotation and cloud permission review.
- Independent penetration test, load test and formal privacy/retention review.

The stack is a production-oriented single-host deployment template, not a managed HA platform. It has no external managed database, object-lock archive, automatic off-host backup scheduler, multi-region failover or external monitoring service. Do not describe it as fully production-certified until those controls and an independent security review are complete.
