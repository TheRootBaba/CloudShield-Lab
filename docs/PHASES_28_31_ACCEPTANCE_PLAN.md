# Phases 28–31 — acceptance and finalization package

**Status date:** 20 November 2026  
**Scope:** Close the remaining engineering-preparation work, make acceptance repeatable, and identify external sign-off that cannot be truthfully completed from this workstation.

## Executive disposition

The repository now contains the core implementation through Phase 27. This package adds a repeatable, secret-safe local verification capture and a single acceptance map for the remaining phases. It does **not** claim that live cloud tenants, production write actions, a multi-host service, or an independent security assessment have passed.

| Phase | Engineering preparation | External acceptance | Release status |
|---|---|---|---|
| 28 — Live provider acceptance | Existing AWS/Azure read-only adapters and tenant identity boundaries; operator acceptance checklist | Dedicated AWS and Azure sandbox accounts, role/identity configuration, provider-side evidence | **Open — account owner action** |
| 29 — Production response adapters | Response plans, approval quorum, digest binding, idempotency, kill switch and fail-closed adapter boundary | Reviewed action-specific write adapters, isolated drills, compensation/rollback evidence | **Open — deliberately disabled** |
| 30 — Distributed operations | Single-host worker leases, heartbeat, bounded retries, backup/restore tooling and operations runbooks | Durable multi-host queue/coordination, central monitoring/paging, load/failover and off-host restore drills | **Open — production infrastructure required** |
| 31 — Independent assurance | 40-case/19-rule regression corpus, security controls, threat model and repeatable local evidence capture | Independent penetration/tenant-isolation test, remediation retest, representative labelled telemetry | **Open — assessor and data owner required** |

## Evidence capture

Run from the repository root in the configured development environment:

```powershell
python scripts/capture-release-evidence.py
```

The command runs:
- Python unit and API regression tests
- Python compilation
- Bandit source scan
- Curated detection evaluation
- Production dependency audit
- Frontend production build

It writes a compact JSON record to `evidence/acceptance/local-verification.json`. The record includes the commit, UTC timestamp, check names, exit codes, durations and bounded output summaries. It does not read `.env` files, print environment values, contact cloud providers, provision resources or run destructive actions.

The frontend build can refresh generated web assets. Review the resulting diff and restore generated files if the build output is not intended for this change.

## Phase 28 — live provider acceptance

Perform in dedicated, disposable AWS and Azure sandboxes only.

1. Create separate least-privilege identities for each CloudShield workspace.
2. Confirm the AWS role trust binds the exact ExternalId and expected principal; restrict permissions to read-only CloudTrail and the approved inventory calls.
3. Confirm Azure workload identity binds the expected tenant, subscription and managed identity; grant only the required Activity Log and inventory read permissions.
4. Record provider account/tenant identifiers in the private acceptance record, never in public screenshots or logs.
5. Verify each workspace can collect only from its own configured identity and scope.
6. Test expired credentials, denied permissions, throttling, timeouts, partial pages and retry bounds.
7. Remove temporary identities, grants and test resources.
8. Obtain the account owner's dated sign-off and attach redacted provider-side evidence.

**Exit evidence:** AWS and Azure acceptance reports, permission snapshots, collection summaries, negative-test results, cleanup confirmation and owner approval. Synthetic fixtures do not satisfy this gate.

## Phase 29 — response execution

Do not enable cloud writes as part of this documentation tranche.

1. Select one narrowly scoped action per provider and define explicit preconditions and resource allowlists.
2. Implement the adapter behind the existing fail-closed boundary; reject unknown action types and stale plan digests.
3. Bind execution to fresh provider state, an independent approval quorum, expiry, idempotency key and the emergency kill switch.
4. Require dry-run output to match the planned target set and blast-radius estimate.
5. Implement compensating action/rollback and prove it with isolated disposable resources.
6. Test approval revocation, duplicate requests, partial failure, timeout, provider throttling and kill-switch activation.
7. Have a reviewer other than the implementer inspect the adapter and drill evidence.

**Exit evidence:** code review, policy diff, before/after provider state, immutable audit records, rollback proof and independent sign-off. Until then the response adapter must remain absent and cloud writes disabled.

## Phase 30 — distributed operations

1. Choose PostgreSQL or a durable managed queue; document delivery semantics, lease ownership, retries, dead-letter handling and idempotency.
2. Replace SQLite lease coordination before running more than one worker host.
3. Define service SLOs, error budgets, retention, alert routing, escalation and named on-call ownership.
4. Export structured logs and low-cardinality metrics to an independently managed monitoring service.
5. Run bounded load, worker crash/reclaim, dependency outage, network partition and failover exercises.
6. Run encrypted off-host backup and isolated restore drills; record achieved RPO/RTO.
7. Test recovery of both the authentication database and every tenant database.

**Exit evidence:** architecture decision record, deployed infrastructure, dashboard and paging proof, load/failover reports, backup object references and witnessed restore results.

## Phase 31 — independent assurance and detection quality

1. Engage an independent assessor with cloud multi-tenant application experience.
2. Supply the threat model, data-flow diagrams, least-privilege policy, API role matrix and test accounts.
3. Test authentication/session handling, tenant isolation, authorization, SSRF/egress, injection, secrets, evidence integrity, dependency/supply-chain controls and response approvals.
4. Track findings by severity and owner; resolve and independently retest all critical/high findings.
5. Obtain consented, privacy-reviewed and independently labelled telemetry from representative environments.
6. Measure per-rule precision, recall, false-positive rate and coverage by provider/service; report confidence intervals and dataset limitations.
7. Keep synthetic fixture results separate from field performance claims.

**Exit evidence:** signed assessment report, remediation/retest ledger and a reproducible detection-quality report with dataset provenance.

## Release decision

A local green build is necessary but not sufficient. Do not call CloudShield production-ready, production-certified, high-availability, or independently secure until the corresponding external gates above have passed and their evidence has been reviewed. Keep the emergency response kill switch enabled and cloud write execution disabled until Phase 29 exit criteria are met.
