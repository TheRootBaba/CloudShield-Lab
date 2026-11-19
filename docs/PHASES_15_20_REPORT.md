# Phase 15–20 offline delivery report

**Date:** 19 November 2026  
**Repository:** TheRootBaba/CloudShield-Lab  
**Base:** merged `main` commit `250cef0` (PR #8)  
**Scope:** offline/local work only; AWS live validation explicitly deferred.

## Executive result

This delivery advances the offline product with API role-token enforcement, rate limiting, request validation, security headers, mutation audit records, evidence bundle v1.1 provenance/version checks, explicit detection confidence semantics, security/operations/retention/evaluation/provider-adapter documentation and regression tests. It does **not** make CloudShield a hosted production product or claim that all six roadmap phases have passed their external acceptance gates.

## Phase status

### Phase 15 — application security hardening

**Implemented in this offline tranche:**
- Optional unique role-specific bearer tokens (`admin`, `responder`, `analyst`), minimum 32 characters, constant-time comparison and fail-closed behavior when token configuration is present.
- RBAC: analysts can read and verify bundles; responders can mutate workflow, add notes, ingest and simulate; admin-only AWS collector invocation.
- Per-IP in-memory sliding-window limits (120 reads/minute, 30 writes/minute).
- Strict JSON object input, UTF-8 JSON validation, content-type and content-length checks, transfer-encoding rejection, 2 MiB body cap and cross-origin Origin rejection.
- CSP, nosniff, frame denial, referrer, permissions and no-store headers.
- SQLite audit records for workflow updates, incident notes, evidence ingestion, simulation and collector invocation. No bodies or tokens are logged.
- Threat model and deployment boundary documented.

**Not complete for hosted exposure:** browser UI login/token lifecycle, MFA/SSO, short-lived/revocable sessions, tenant isolation, distributed rate limiting, managed secrets, TLS ingress, external immutable audit sink and independent penetration testing. Server remains loopback-only.

### Phase 16 — evidence integrity and chain of custody

**Implemented:** evidence bundle v1.1 with producer/version, generated/export time, explicit collection scope, source-format provenance, event counts, manifest digest and strict version/provenance verification. Existing SHA-256 per-record checks and optional detached Ed25519 signing remain. Added unknown-version and missing-provenance tests. Documented independent public-key trust, overlap key rotation, retention/deletion and incident response.

**Not complete:** trusted timestamp authority, external WORM archive, immutable key registry and legal/organizational retention automation. Local host time and SQLite remain operator-controlled.

### Phase 17 — detection quality and evaluation

**Implemented:** added explicit HIGH/MEDIUM confidence tier and human-readable confidence rationale to each finding; documented severity/confidence meaning, corpus limitations, regression methodology, duplicate/missing/out-of-order timestamp coverage and a future independent-label process.

**Verification boundary:** current fixture corpus is 26 hand-labelled cases. Its results are deterministic regression results only, not production precision/recall. Representative labelled telemetry, confidence calibration and operational false-positive/false-negative rates remain outstanding.

### Phase 18 — cloud integrations and inventory

**Deferred by instruction:** no live AWS integration, credential use, API calls, multi-region or organization inventory validation, or cloud resources. Added a provider-adapter contract covering bounded pagination, transient retries/backoff, partial failures, permission reporting, provenance and least-privilege validation. Existing AWS adapters remain opt-in and mock-tested only.

### Phase 19 — deployment and operations

**Designed/documented:** supported loopback deployment, environment configuration, secret-handling guidance, build/run steps, backup and restore procedure, health/logging, recovery, rollback and hosted-deployment prerequisites.

**Not complete:** no production container/orchestrator or public deployment is approved because the UI has no browser authentication lifecycle and the service is single-tenant. No independent backup restore exercise, monitoring stack, alerting integration or hosting budget was provided.

### Phase 20 — final assurance and release

**Prepared:** release assurance checklist, risk register, support policy, offline test gates and explicit external assurance gates.

**Not complete:** independent security review/penetration test, real AWS validation, performance/load testing at production scale, backup restoration exercise and production incident-response exercise. These require external environment, people or approval and cannot honestly be self-certified in this code pass.

## Cost and cloud boundary

No AWS credentials were read, no AWS API calls were made, no cloud resources were created/modified/deleted and no hosting was provisioned. AWS collector and inventory remain opt-in and disabled by default. Cloud spend for this pass: **$0 by design** (no cloud activity initiated).

## Validation results

Local verification on the Windows development machine (Python 3.14):

| Check | Result |
|---|---|
| Python compilation | Passed (`python -m compileall -q src tests`) |
| Python unit/integration suite | 79 tests passed |
| Detection evaluation | 26/26 curated fixture cases passed; micro precision/recall/specificity/F1 = 1.0 on this fixture set only |
| React/Vite production build | Passed; main JS 407.27 kB, overview chunk 471.22 kB |
| Terraform formatting | Passed (`terraform fmt -check -recursive terraform`) |
| Terraform secure root validation | Passed |
| Terraform vulnerable training root validation | Passed |
| npm production dependency audit | 0 vulnerabilities (`npm audit --omit=dev`) |
| Python dependency audit | No known vulnerabilities in isolated project environment with AWS/signing extras (`pip-audit --skip-editable`; editable project itself is not published to PyPI) |
| Git whitespace check | Passed (`git diff --check`) |

The GitHub Actions workflow upgrades pip and includes a Python `pip-audit --skip-editable` scan of the installed AWS/signing dependencies in addition to the existing npm audit, tests, build and Terraform checks. That CI workflow has not yet run for this unpushed branch. No browser-based remote deployment, penetration test, load test or backup-restore exercise was performed.

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
