# Deployment and operations design (offline scope)

## Supported operating mode

The supported mode remains a single-user process bound to `127.0.0.1:8765`, with SQLite on a local disk. Do not bind to `0.0.0.0`, publish the Python listener, or treat the application as multi-tenant. Optional role bearer tokens add API authorization but do not change the loopback bind restriction or provide a complete browser login experience.

## Configuration

- `CLOUDSHIELD_HOST`: loopback IP only; non-loopback startup is rejected.
- `CLOUDSHIELD_PORT`: local listener port (default 8765).
- `CLOUDSHIELD_DB`: evidence database path; protect it with OS account and filesystem ACLs.
- `CLOUDSHIELD_ADMIN_TOKEN`, `CLOUDSHIELD_RESPONDER_TOKEN`, `CLOUDSHIELD_ANALYST_TOKEN`: optional unique random secrets, at least 32 characters. If configured, every API route except health requires a bearer token.
- `CLOUDSHIELD_ENABLE_AWS_COLLECTOR`: must remain unset/disabled in the offline zero-cost milestone.
- `CLOUDSHIELD_ENABLE_AWS_INVENTORY`: must remain unset/disabled in the offline zero-cost milestone.

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

A public deployment is not delivered. It requires a managed TLS ingress, identity-aware frontend/token lifecycle, multi-user/tenant authorization, external secret storage, central audit retention, monitoring/alerting, tested backup automation, incident response ownership and a separately approved hosting budget. Container orchestration is deferred because the current single-tenant UI has no browser login/token lifecycle and the API intentionally binds to loopback.
