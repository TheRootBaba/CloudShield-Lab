# Phase 15–20 offline delivery report

**Date:** 19 November 2026  
**Repository:** TheRootBaba/CloudShield-Lab  
**Base:** merged `main` commit `250cef0` (PR #8)  
**Scope:** offline/local work only; AWS live validation explicitly deferred.

## Executive result

This delivery advances the product with API role-token enforcement and optional browser password/session authentication, server-enforced roles, per-workspace SQLite isolation, CSRF controls, auth audit, multi-workspace recovery, a Caddy HTTPS deployment profile, evidence provenance, detection evaluation and regression tests. It does **not** make CloudShield a hosted production product or claim that all six roadmap phases have passed their external acceptance gates.

## Phase status

### Phase 15 — application security hardening

**Implemented in this offline tranche:**
- Optional unique role-specific bearer tokens (`admin`, `responder`, `analyst`), minimum 32 characters, constant-time comparison and fail-closed behavior when token configuration is present.
- RBAC: analysts can read and verify bundles; responders can mutate workflow, add notes, ingest and simulate; admin-only AWS collector invocation.
- In-memory sliding-window limits keyed to the TCP peer (120 reads/minute, 30 writes/minute); forwarded client headers are not trusted.
- Strict JSON object input, UTF-8 JSON validation, content-type and content-length checks, transfer-encoding rejection, 2 MiB body cap and cross-origin Origin rejection.
- CSP, nosniff, frame denial, referrer, permissions and no-store headers.
- SQLite audit records for workflow updates, incident notes, evidence ingestion, simulation and collector invocation. No bodies or tokens are logged.
- Threat model and deployment boundary documented.

**Core browser login and tenant isolation now implemented:** first-admin bootstrap, invitation-only registration, scrypt password hashes, 12-hour sessions, logout/member revocation, CSRF and separate tenant databases. **Still not complete for hosted exposure:** MFA/SSO, email verification, password recovery, distributed rate limiting, managed secrets, external immutable audit sink and independent penetration testing. Production Caddy/Compose profile is authored but not deployed.

### Phase 16 — evidence integrity and chain of custody

**Implemented:** evidence bundle v1.1 with producer/version, generated/export time, explicit collection scope, source-format provenance, event counts, manifest digest and strict version/provenance verification. Existing SHA-256 per-record checks and optional detached Ed25519 signing remain. Added unknown-version and missing-provenance tests. Documented independent public-key trust, overlap key rotation, retention/deletion and incident response.

**Not complete:** trusted timestamp authority, external WORM archive, immutable key registry and legal/organizational retention automation. Local host time and SQLite remain operator-controlled.

### Phase 17 — detection quality and evaluation

**Implemented:** added explicit HIGH/MEDIUM confidence tier and human-readable confidence rationale to each finding; documented severity/confidence meaning, corpus limitations, regression methodology, duplicate/missing/out-of-order timestamp coverage and a future independent-label process.

**Verification boundary:** current fixture corpus is 30 hand-labelled cases. Its results are deterministic regression results only, not production precision/recall. Representative labelled telemetry, confidence calibration and operational false-positive/false-negative rates remain outstanding.

### Phase 18 — cloud integrations and inventory

**Offline adapters implemented in the follow-up extension:** bounded, read-only AWS and Azure collectors with retry/pagination/partial-failure handling, provenance, CLI/API routes and mocked tests. No live AWS/Azure credentials, API calls, account/subscription validation or cloud resources were used. The adapters remain opt-in; multi-tenant shared credentials are blocked until per-tenant identities exist.

### Phase 19 — deployment and operations

**Designed/documented:** supported loopback deployment, environment configuration, secret-handling guidance, build/run steps, backup and restore procedure, health/logging, recovery, rollback and hosted-deployment prerequisites.

**Offline deployment work delivered:** browser password/session auth and workspace isolation, production Caddy/Compose profile, private internal-only app network, first-admin bootstrap secret, guarded deployment script, and quiesced multi-workspace backup/recovery scripts. **Not complete:** no real host/domain deployment or actual production restore drill was possible because the local Docker engine and approved hosting target are unavailable; monitoring, alerting, off-host backup ownership and independent review remain external.

### Phase 20 — final assurance and release

**Prepared:** release assurance checklist, risk register, support policy, offline test gates and explicit external assurance gates.

**Not complete:** independent security review/penetration test, live AWS/Azure validation, performance/load testing at production scale, restore exercise on an actual production host with off-host media, and production incident-response exercise. These require external infrastructure, people or approval and cannot honestly be self-certified in this code pass.

## Cost and cloud boundary

No AWS credentials were read, no AWS API calls were made, no cloud resources were created/modified/deleted and no hosting was provisioned. AWS collector and inventory remain opt-in and disabled by default. Cloud spend for this pass: **$0 by design** (no cloud activity initiated).

## Validation results

Local verification on the Windows development machine (Python 3.14):

| Check | Result |
|---|---|
| Python compilation | Passed (`python -m compileall -q src tests`) |
| Python unit/integration suite | 121 tests passed (latest run after auth hardening) |
| Detection evaluation | 30/30 curated fixture cases passed; micro precision/recall/specificity/F1 = 1.0 on this fixture set only |
| React/Vite production build | Passed; main JS 418.16 kB, overview chunk 471.22 kB |
| Terraform formatting | Passed (`terraform fmt -check -recursive terraform`) |
| Terraform secure root validation | Passed |
| Terraform vulnerable training root validation | Passed |
| npm production dependency audit | 0 vulnerabilities (`npm audit --omit=dev`) |
| Python dependency audit | No known vulnerabilities in pinned `requirements-cloud.lock` (AWS/Azure/signing runtime dependencies) |
| Git whitespace check | Passed (`git diff --check`) |

The GitHub Actions workflow upgrades pip and includes a Python `pip-audit --skip-editable` scan of the installed AWS/signing dependencies in addition to the existing npm audit, tests, build and Terraform checks. That CI workflow has not yet run for this unpushed branch. No public production-host deployment, penetration test, load test or production-host restore exercise was performed; the automated local workspace backup/restore/authentication test passes.

## Files added

- `docs/SECURITY_THREAT_MODEL.md`
- `docs/EVIDENCE_CUSTODY.md`
- `docs/DETECTION_EVALUATION.md`
- `docs/CLOUD_ADAPTER_DESIGN.md`
- `docs/DEPLOYMENT_OPERATIONS.md`
- `docs/RELEASE_ASSURANCE.md`
- `docs/PHASES_15_20_REPORT.md`


## Follow-up extension: dual-provider and local operations work

A follow-up extension adds Azure as a second provider, AWS pagination/partial-failure resilience, Azure detection regression cases, automated SQLite backup/restore commands, local-only container packaging and a trusted timestamp/WORM design. See `docs/PROVIDER_EXPANSION_REPORT.md` for exact current test results. These additions do not remove the external hosted-production or live-cloud validation gates listed above.
