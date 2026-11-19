# Deployment and operations design (offline scope)

## Supported operating mode

Legacy local mode remains a single-user process bound to loopback. Optional multi-user mode adds browser password/session authentication and separate SQLite workspaces. The production Compose profile uses Caddy HTTPS ingress and keeps the Python API private; it is a single-host deployment template and has not been deployed to a public host.

## Configuration

- `CLOUDSHIELD_HOST`: loopback by default; the supplied production container profile uses a wildcard bind only inside the container and is reachable through Caddy on a private Docker network.
- `CLOUDSHIELD_PORT`: local listener port (default 8765).
- `CLOUDSHIELD_DB`: evidence database path; protect it with OS account and filesystem ACLs.
- `CLOUDSHIELD_BOOTSTRAP_TOKEN`: required on non-loopback deployments; a unique random first-administrator setup key of at least 32 characters. The public signup page requires it only while the first administrator is being created.
- `CLOUDSHIELD_ADMIN_TOKEN`, `CLOUDSHIELD_RESPONDER_TOKEN`, `CLOUDSHIELD_ANALYST_TOKEN`: optional unique random secrets, at least 32 characters for legacy local bearer-token mode. Multi-user browser mode uses database-backed sessions instead.
- `CLOUDSHIELD_ENABLE_AWS_COLLECTOR`: must remain unset/disabled in the offline zero-cost milestone.
- `CLOUDSHIELD_ENABLE_AWS_INVENTORY`: must remain unset/disabled in the offline zero-cost milestone.
- `AZURE_SUBSCRIPTION_ID`: one explicit Azure subscription scope; no secret.
- `CLOUDSHIELD_ENABLE_AZURE_COLLECTION`: must remain unset/disabled until Azure read-only validation is separately approved.

Use an OS secret manager or protected service environment file; do not store tokens in Git, shell history, screenshots or logs. Restart the process after rotation.

## Build and local run

```powershell
python -m pip install -e ".[signing]"
python -m compileall -q src tests
python -m unittest discover -s tests -v
npm ci
npm run build
python -m cloudshield.api
```

The Vite build outputs static files under `web/`. The Python process serves the UI and API together. Keep the database on a persistent local volume with restrictive permissions. Do not put the database in a synced/shared directory.

## Automated SQLite backup and recovery

Use the online SQLite backup command so committed WAL data is included consistently:

```powershell
cloudshield backup --database artifacts/evidence.sqlite3 --output artifacts/backups/evidence.sqlite3
cloudshield verify-backup artifacts/backups/evidence.sqlite3
cloudshield restore-backup artifacts/backups/evidence.sqlite3 --destination artifacts/restore/evidence.sqlite3
```

The backup command refuses overwrite, performs `PRAGMA integrity_check`, writes a SHA-256 sidecar manifest and restricts local file permissions where supported. Verification checks file name, size, digest and SQLite integrity. Restore refuses an existing destination and verifies before copying. Keep the manifest in a separate trusted location or sign it; an unsigned sidecar stored next to a backup does not protect against an attacker who can alter both.

## Backup and recovery runbook

1. Stop CloudShield before copying the SQLite database (or use SQLite's online backup API in a future managed backup job).
2. Copy the DB and any signing public-key registry into an encrypted, access-controlled backup location.
3. Record backup timestamp, file digest, operator and retention expiry outside the backed-up database.
4. Restore into a new path, run the test suite and verify representative evidence bundles before switching `CLOUDSHIELD_DB`.
5. Preserve the original DB until the restored copy is accepted. Test restore periodically; a successful file copy is not a restore test.

## Health, logs and recovery

`GET /api/health` is a liveness response and intentionally omits secrets. HTTP access logging is disabled unless explicitly enabled. Security audit rows record mutation actor/role, action, resource identifier, remote address and timestamp, but not request bodies or tokens. Protect the SQLite file and review audit entries during incident response. Restart the process after an unexpected exit; inspect local stderr and filesystem health. Do not enable verbose logs in a public environment without reviewing sensitive-data exposure.

## Release and rollback

Build from a clean reviewed commit, install from lockfiles, run tests/scans, retain the previous known-good commit and DB backup, then deploy. Roll back code and restore DB only from a compatible backup; take a fresh backup before rollback. Keep schema migration and data compatibility in the release notes.

## Hosting boundary

A public deployment has not been executed. A production-oriented Caddy/Compose profile is authored and configuration-validated, but requires a real host/domain, firewall, protected environment file and operator approval. MFA/SSO, verified email, password recovery, external secret storage, central audit retention, monitoring/alerting, encrypted off-host backup automation, incident response ownership and independent penetration testing remain release gates.

## Containerized local deployment

`Dockerfile` and `compose.yaml` provide a local-only container profile. It uses a non-root user, read-only root filesystem, a writable persistent `/data` volume, no added Linux capabilities, `no-new-privileges`, and a host port binding fixed to `127.0.0.1:8765`. The container-only wildcard bind is gated by `CLOUDSHIELD_CONTAINER_MODE=1`; do not reuse that setting in a public or manually exposed container. Build and run with `docker compose up --build -d`; inspect with `docker compose logs`; stop with `docker compose down` (the named volume persists). The container profile is not a hosted/multi-tenant production deployment.


## Multi-user browser authentication

The optional multi-user mode is implemented. Set CLOUDSHIELD_AUTH_MODE=multi_user; the first signup bootstraps the administrator. Later registrations require a single-use invitation. Passwords are scrypt-hashed, sessions are opaque server-side records with 12-hour expiry, cookies are HttpOnly/SameSite=Strict, and write requests require a CSRF token. CLOUDSHIELD_COOKIE_SECURE=1 is mandatory for non-loopback deployment. See docs/MULTI_USER_AUTH.md for roles, invitation and account lifecycle.

Each workspace's evidence store is a separate SQLite database selected from the authenticated session. Never accept a tenant ID from a client request. The authentication database stores users, sessions, invites and auth audit records. Back up the auth database and every tenant DB together. Shared AWS/Azure server credentials are blocked in multi-user mode until provider identities are tenant-scoped.

## Production HTTPS stack

compose.production.yaml is a single-host production-oriented profile. It keeps the app API private on an internal Docker bridge and exposes only Caddy on 80/443. Caddy handles automatic TLS and security headers. The app container runs non-root with read-only root filesystem, dropped capabilities, no-new-privileges and persistent /data. Set a real domain and TLS email in the untracked .env.production file copied from .env.production.example. Protect that file with host ACLs. Verify DNS, firewall, persistent volumes and off-host backups before starting the stack.

Deployment commands on the host:
    cp .env.production.example .env.production
    # Generate a unique value and set CLOUDSHIELD_BOOTSTRAP_TOKEN in .env.production:
    python -c 'import secrets; print(secrets.token_urlsafe(48))'
    chmod 600 .env.production
    docker compose --env-file .env.production -f compose.production.yaml config --quiet
    docker compose --env-file .env.production -f compose.production.yaml up --build -d
    docker compose --env-file .env.production -f compose.production.yaml ps
    docker compose --env-file .env.production -f compose.production.yaml logs --tail=100 caddy cloudshield

The API container does not publish a host port. Do not add a direct mapping for port 8765. Startup refuses a non-loopback bind unless multi-user auth, Secure cookies and a strong initial-admin setup key are configured. Caddy is the only ingress. The application sits on an internal-only Docker network with no direct internet egress; Caddy is dual-homed to that network and a separate edge network for certificate issuance. The bootstrap secret is passed only to the application container, not the proxy. Public DNS, host firewall, a protected deployment secret file, monitoring, off-host backup storage and independent penetration testing remain deployment-owner responsibilities.

## Multi-tenant workspace recovery

Use the workspace-set commands rather than backing up only the legacy database:
    cloudshield backup-workspaces --auth-database /data/auth.sqlite3 --tenant-directory /data/tenants --output /data/backups/cloudshield-workspaces.zip
    cloudshield verify-workspaces /data/backups/cloudshield-workspaces.zip
    cloudshield restore-workspaces /data/backups/cloudshield-workspaces.zip --destination /data/recovery-drill/restored

Quiesce writes to the authentication and tenant databases for a consistent cross-file snapshot. Verification checks the archive digest, internal manifest, exact file list, each SQLite database hash and integrity check. Restore refuses to overwrite and rejects unsafe paths. Keep the outer manifest in a separate protected location; a colocated unsigned hash manifest is not immutable evidence.

Windows deployment scripts are provided: scripts/backup-production.ps1 stops the app during the cross-database snapshot, runs a one-off backup container, verifies the archive, copies the archive and sidecar to a host backup folder, and restarts the app in a finally block. This creates a short maintenance window. scripts/recovery-drill.ps1 verifies and restores to a fresh path, then checks restored authentication and tenant databases without replacing live data.

## Recovery exercise evidence

Automated tests create a real auth database, create an isolated tenant database, ingest synthetic evidence, back up the complete workspace set, verify the archive, restore into a new directory, authenticate using the restored session and verify the restored evidence count. This validates the archive/restore code path in the local test environment. It is not a substitute for a scheduled restore exercise on the actual production host and independent off-host backup media.

## Remaining production security requirements

The delivered password/session implementation is not an enterprise identity service. MFA/WebAuthn, OIDC/SAML, verified email, self-service password reset, session device management, distributed rate limiting, external audit export, external managed secrets, central monitoring/alerting, independent penetration testing, load testing and provider-specific tenant credentials remain unimplemented. The single-host Compose profile is not highly available or production-certified. Do not claim those controls are complete.
