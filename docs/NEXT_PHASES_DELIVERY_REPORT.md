# Phase 21 delivery report — cloud operations and production controls

**Implementation branch:** `feat/firebase-auth-integration`  
**Report date:** 19 November 2026  
**Scope:** tenant-scoped AWS/Azure connections, scheduled collection, alerts, guided response approvals, identity hardening and backup/operations groundwork.

## Executive status

The software implementation for workspace-specific read-only cloud connections, a scheduled collector worker, persistent cloud inventory, high-severity alerts, SMTP notification dispatch, guided response requests with independent approval, Firebase TOTP/SSO client flows, readiness heartbeat and opt-in offsite backup infrastructure has been added.

**This is not a production launch certification.** No real AWS or Azure tenant credentials were supplied, no Terraform infrastructure was applied, no real SMTP message was delivered, Firebase MFA/SSO was not enabled in the Firebase console, no offsite restore drill was run against S3, and no independent penetration test was performed. Those gates cannot be completed by repository changes alone.

## Phase-by-phase implementation

| Workstream | Implemented in code | Verification performed | Remaining acceptance gate |
|---|---|---|---|
| Tenant-scoped AWS | Per-workspace role ARN, unique ExternalId, STS AssumeRole, account-ID check, unique global role binding; no stored access keys | Unit tests verify ExternalId passed to STS, account identity check, duplicate identity rejection, disabled-by-default and test-before-enable | Test with dedicated AWS sandbox role and independently inspect effective IAM permissions |
| Tenant-scoped Azure | Per-workspace tenant/subscription/client ID, managed identity or workload federation, unique identity binding; no client secret or shared developer credential fallback | UUID validation, no-secret storage and unique identity checks | Test in a dedicated Azure tenant/subscription using a real user-assigned or federated workload identity |
| Scheduled collection | Separate Docker worker; 60–3600 second interval (default 300); bounded AWS CloudTrail and Azure Activity Log windows/pages; SDK retries; idempotent ingestion | Worker module compiles; API/auth tests; provider adapter tests; readiness heartbeat test | Run continuously against live accounts; verify throttling, clock skew, event gaps and recovery after worker restart |
| Live inventory | Six-hour scheduled refresh; bounded AWS EC2/security-group/S3-name/IAM metadata and Azure ARM resources; tenant-local persistence and UI | Inventory upsert and provider adapter tests | Confirm coverage/permission boundaries against real subscriptions; expand resource coverage in later phase |
| Alerts | Deduplicated HIGH/CRITICAL workspace alerts, acknowledge workflow, tenant-local storage | API test creates synthetic findings, reads alerts and acknowledges them | Validate alert precision and escalation with representative telemetry |
| Member notifications | Worker SMTP outbox; STARTTLS and mounted password file; recipients limited to active workspace admins/responders; bounded retries | Mock SMTP test verifies recipients and that raw event payload is not emailed | Configure a real SMTP relay and verify delivery, bounce handling and recipient policy |
| Guided response | Finding-specific containment guidance, required rationale, request queue, independent admin approval/rejection, audit trail | API test verifies request, self-approval denial, independent approval and no execution flag | No cloud writes exist yet. Build provider-specific action adapters only after threat modeling, sandbox testing, rollback and independent review |
| MFA | Firebase TOTP enrollment UI (manual secret / otpauth URI), challenge flow and factor management | Frontend production build; Firebase SDK enrollment calls compile | Enable Identity Platform/TOTP in Firebase, enroll real user factors, test recovery and enforce only after enrollment |
| SSO | Firebase OIDC/SAML provider sign-in flow with configured provider ID | Frontend production build | Configure provider metadata, claims, domain/authorized redirect URLs and test real IdP sign-in |
| Monitoring | Liveness/readiness endpoint, worker heartbeat, Docker health checks and provider last-error/timestamps | API readiness test verifies worker heartbeat transitions | Centralized metrics/logging, alert routing, SLOs, on-call, failover and host-level monitoring |
| Offsite backup | New Terraform backup root (KMS/S3/Object Lock/least-privilege uploader role), offsite upload and isolated restore-drill scripts; backup script stops app and worker writers | Terraform formatting and validate; scripts syntax review; existing archive/restore unit suite | Apply in a dedicated AWS account, upload an actual archive, restore from S3, record RPO/RTO and run recurring drills |
| Independent assurance | Release gate documented | Automated source checks and CI pipeline integration | Independent penetration test, threat-model review, load test and formal sign-off remain outstanding |

## Important safety decisions

1. Cloud provider connections start disabled and cannot be enabled until a successful connection test.
2. A workspace cannot bind the same AWS role ARN or the same Azure tenant/subscription/client identity as another workspace.
3. Cloud collection endpoints are administrator-only and read-only.
4. Alert email contains only alert title/severity/reference, not raw cloud events or credentials.
5. Response approval is not execution. The execution function fails closed; no AWS/Azure write calls are present.
6. Backup Terraform creates zero resources by default. COMPLIANCE Object Lock is irreversible for the retention period and requires legal approval.
7. MFA/SSO are client-side Firebase integration points; actual policy enforcement and provider metadata must be configured in Firebase Identity Platform.

## Verification record

The following are run during the implementation session; final CI results will be appended after the full validation run:

- New cloud operations unit tests cover workspace bindings, AWS AssumeRole ExternalId, disabled-by-default, test-before-enable, high-severity alert deduplication, inventory upsert, independent response approval, fail-closed execution and mocked SMTP delivery.
- Multi-user API tests cover provider configuration/role restrictions, alerts, independent approval and worker readiness heartbeat.
- React/Vite production build passes after lazy-loading the cloud operations, account security and Firebase Auth modules: main entry 454.12 kB, Overview 473.90 kB, Firebase Auth shared chunk 128.18 kB; no chunk-size warning.
- Terraform secure, vulnerable-training and offsite-backup roots all initialize and validate; recursive formatting checks pass.
- Production Compose plus optional SMTP overlay parses with test-only environment values; the Docker image builds successfully.
- 168 Python unit/integration tests pass; authentication/recovery coverage is 95% (auth 97%, recovery 92%). Bandit reports zero findings and npm production dependency audit reports zero vulnerabilities.
- PowerShell backup/offsite/local-start scripts parse successfully; git diff whitespace check passes.
- Rebuilt the local production Compose stack without stopping it permanently: CloudShield API, Caddy and collector worker are healthy; HTTPS UI, liveness and public readiness endpoints all returned HTTP 200. The readiness response reported the worker heartbeat as current. Caddy host ports remain bound to 127.0.0.1 only.
- Live AWS/Azure, SMTP, Firebase Identity Platform, S3 Object Lock, and offsite restore remain unverified by design.

## Next phases

### Phase 22 — live integration acceptance
- Deploy a disposable AWS account and Azure subscription.
- Configure customer-specific IAM role / Azure managed identity, validate least privilege and identity uniqueness.
- Test event completeness, retry/backoff, duplicate ingestion, pagination, throttling and provider outage recovery.
- Validate inventory snapshots, partial-failure semantics and tenant separation with two real workspaces.
- Run an alert triage exercise with responder/admin accounts and verify SMTP delivery.

### Phase 23 — controlled response execution
- Define action-specific permissions and preconditions for each response.
- Add dry-run plans, blast-radius preview, approval quorum, idempotency keys, timeouts, rollback/compensation and a global kill switch.
- Execute only in isolated test accounts, record before/after evidence and independently review.
- Keep automatic response disabled until every action passes the safety gates.

### Phase 24 — production operations and resilience
- Deploy centralized metrics/log aggregation, pager routing and SLO/error-budget dashboards.
- Apply the Object Lock backup target and perform off-host restore drills with documented RPO/RTO.
- Add multi-instance worker leasing/leader election, durable job queue and database migration/backup strategy before horizontal scaling.
- Perform load, failover, disaster-recovery and secret-rotation exercises.

### Phase 25 — independent assurance
- Commission an independent penetration test and tenant-isolation review.
- Review Firebase MFA/SSO policy, session lifecycle, provider trust policies, SMTP handling and backup retention.
- Fix findings, repeat tests and obtain signed release approval.

### Phase 26 — coverage expansion
- Expand authoritative inventory, organization/account discovery, configuration posture and data-plane telemetry.
- Build representative labeled production detection datasets and measure false-positive/false-negative rates.
- Add richer alert routing and case management integrations after privacy and access-control review.

## Release decision

**Not production-ready / not certified.** The Phase 21 code foundation and automated verification are in place, but the external acceptance gates above must be completed before describing CloudShield as a fully operational managed cloud security platform.
