# Phases 23–26 implementation and acceptance report

**Branch:** `feat/phases-23-26-controlled-response-resilience`
**Base:** merged `main` at `284fa96394a6755df3d13308d5b1ba02e6d4156c`
**Scope:** guarded response orchestration, collector coordination/operational counters, security-assurance preparation, and AWS/Azure detection coverage expansion.

## Executive result

This tranche adds tested software controls for response planning, multi-approval, idempotency, kill-switch enforcement, worker leasing, service metrics, and additional Azure detections. It does **not** certify production readiness. In particular, no production cloud-write adapter is installed, SQLite leases are single-host/shared-volume coordination only, and no independent penetration test or live cloud recovery/failover exercise has been performed.

## Phase 23 — controlled response execution

### Implemented
- Action recommendations are narrowed to the relevant AWS detection family. Policy/trust changes and Azure findings no longer receive unrelated AWS credential-revocation suggestions.
- Deterministic, expiring dry-run plans are stored with a SHA-256 plan digest.
- Plans expose explicit resource targets, inventory matches, unresolved targets, action parameters, missing preconditions, risk, required permission and blast-radius scope.
- Dry-run is non-mutating and never calls a cloud provider.
- The initial request approval is independent from the requester. Sensitive execution requires two additional distinct administrator approvals bound to the exact plan digest.
- Requester and initial approver cannot approve execution.
- A service-wide kill switch is persisted in the shared auth database and is enabled by default. Workspace administrators can only re-enable the stop switch; disabling requires a local deployment operator and an exact confirmation phrase through the CLI.
- Execution requires deployment opt-in, the kill switch to be explicitly disabled, a valid unexpired plan digest, resolved inventory targets, approval quorum and a caller-supplied idempotency key.
- One execution attempt is permitted per response request. Failed/attempted requests cannot be replayed with a new key.
- Execution history stores the adapter result, failure code and adapter-supplied rollback metadata. API endpoints enforce responder/admin role boundaries and audit mutations.

### Verification
- Unit tests cover dry-run determinism, no provider invocation during planning, request approval gating, actor separation, two-person execution quorum, default-on kill switch, idempotency/replay rejection, and adapter success/failure behavior using a test fake.
- The existing legacy execution entry point remains fail-closed.

### Remaining release gate
**No production AWS/Azure write adapter is installed.** The tested adapter seam is not equivalent to a live containment action. Implementing and validating provider-specific writes requires isolated cloud accounts, explicit least-privilege write policies, resource-state precondition checks, before/after evidence, real compensation/rollback drills and independent review. Until then, CloudShield must not be represented as performing cloud remediation.

## Phase 24 — production resilience

### Implemented
- Shared-auth-database worker lease table with per-workspace lease names, owner identity, expiry, owner-checked renewal before/after bounded provider SDK operations, owner-checked release and stale-lease reclamation.
- Unique per-process worker IDs and per-worker heartbeats.
- Worker cycles, errors and lease contention counters.
- `GET /api/metrics` returns service-wide low-cardinality counters and fresh running-worker count; in authenticated mode it is administrator-only.
- Readiness now understands the new worker heartbeat table while retaining compatibility with the previous primary heartbeat table.

### Verification
- Unit tests cover single-owner lease acquisition, owner-only renewal/release, expired lease reclamation, multiple worker heartbeats and monotonic operational counters.
- Worker collection is protected by a per-workspace lease, preventing two replicas sharing the same supported auth database from simultaneously collecting the same workspace.

### Remaining release gate
The lease backend is SQLite. It requires a reliable shared local/volume filesystem and is not a distributed database or safe multi-region coordinator. Before multi-host scaling, migrate leases/jobs to PostgreSQL or a durable queue. Central log aggregation, alert routing/paging, SLO/error-budget dashboards, real load/failover tests, off-host restore drills and an on-call rota remain operational acceptance work.

## Phase 25 — independent security assurance

### Implemented preparation
- Response routes enforce explicit role checks and audit every mutation.
- Execution fails closed unless a deployment opt-in, explicit kill-switch disable, plan digest, quorum and reviewed adapter are all present.
- Security controls and residual limitations are documented in the operations and threat-model documents.
- Existing CI/source checks remain the automated baseline: unit tests, coverage, Bandit, dependency audits, Terraform validation and container/web builds.

### Remaining release gate
An independent penetration test, independent tenant-isolation assessment, secrets/identity review, external audit-log review and signed remediation closure have **not** been performed. Automated tests and source scans are not substitutes for an independent assessor. This phase is not complete for production certification.

## Phase 26 — detection and coverage expansion

### Implemented
Four additional Azure Activity Log rules:
- `CS-AZ-NET-001`: unrestricted source to SSH/RDP/all destination ports in an NSG rule.
- `CS-AZ-STO-001`: storage account public blob access enabled.
- `CS-AZ-GOV-001`: Azure Policy assignment deleted.
- `CS-AZ-KV-001`: Key Vault network ACL default action set to Allow.

The curated regression corpus now contains 40 hand-labelled AWS/Azure event-shape cases against 19 catalogued rules, including negative controls for private NSG sources, disabled public blob access, policy assignment writes and Key Vault deny defaults. The existing pipeline already creates investigation timelines, groups findings by actor/account within a bounded time window, and builds explainable temporal/resource correlation graphs; the expanded Azure findings flow through that same pipeline.

### Verification
The deterministic evaluation suite checks that all curated cases match their expected rule sets. These fixture metrics describe only the hand-authored corpus; they are not production precision/recall estimates.

### Remaining release gate
No representative customer telemetry corpus, production false-positive/false-negative measurement, suppression tuning, richer multi-event correlation model, Defender for Cloud/Entra ID data-plane coverage, or multi-account organization discovery is included. Those require separately sourced and privacy-reviewed datasets and provider acceptance.

## Merge and release status

- PR #12 is already merged into `main` at `284fa963`; the old conflict banner is stale.
- This tranche is on a new branch based on that merged commit. It must be validated and reviewed as a new change set.
- No AWS/Azure cloud mutation, real containment, independent pentest, production load test, or offsite restore was run as part of this tranche.
- Do not enable `CLOUDSHIELD_RESPONSE_EXECUTION_ENABLED=1` in production. No reviewed production adapter is installed, and the emergency kill switch must remain enabled.

## Next acceptance work

1. Add and independently review provider-specific AWS/Azure response adapters in isolated test accounts, including rollback and idempotency tests.
2. Move distributed scheduling to PostgreSQL/durable queue before deploying multiple hosts.
3. Connect centralized logs, metrics, paging, SLOs and operational ownership; run measured load/failover and offsite restore drills.
4. Commission independent penetration and tenant-isolation testing; resolve and retest findings.
5. Expand detection corpus with independently labelled, representative and privacy-reviewed telemetry; measure precision/recall by provider and rule.

**Release posture: implementation tranche complete; production certification remains gated by the external acceptance items above.**
