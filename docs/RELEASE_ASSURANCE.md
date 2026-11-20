# Release assurance

This checklist separates code-level verification from external production acceptance. A checked software control is not proof that an external provider, identity service or operational environment has been tested.

## Automated engineering baseline

- [x] Python unit and API regression suite for authentication, tenant isolation, detection, storage, evidence, worker coordination and response orchestration.
- [x] Python compilation and Bandit source scan.
- [x] Deterministic 40-case AWS/Azure detection evaluation across 19 catalogued rules.
- [x] Production dependency audit and frontend build in CI.
- [x] Terraform formatting/validation and container build in CI.
- [x] Response guardrails: expiring action plans, plan digest, independent approvals, quorum, idempotency, kill switch and fail-closed adapter boundary.
- [x] Workspace-specific AWS/Azure connection configuration and shared identity ownership reservation.
- [x] Worker leases, renewal, expiry/reclaim, heartbeats and operational counters.

## External production acceptance — open

- [ ] Live AWS sandbox tenant-binding, AssumeRole and bounded collection acceptance.
- [ ] Live Azure sandbox tenant-binding, workload identity and Activity Log collection acceptance.
- [ ] Reviewed AWS/Azure write adapters, controlled containment drills and real rollback evidence.
- [ ] PostgreSQL or durable-queue worker coordination before multi-host operation.
- [ ] Centralized log aggregation, paging, dashboards, SLOs and on-call ownership.
- [ ] Load, failover and recovery exercises under documented operational limits.
- [ ] Off-host backup restore drill in an isolated environment.
- [ ] Firebase Identity Platform MFA policy and real TOTP enrollment acceptance.
- [ ] OIDC/SAML provider configuration and end-to-end identity acceptance where required.
- [ ] SMTP relay delivery, retry and bounce handling acceptance where required.
- [ ] Independent penetration test and tenant-isolation assessment.
- [ ] Critical/high findings resolved, independently retested and signed off.
- [ ] Detection quality evaluated on representative labelled telemetry.

## Release policy

CloudShield must remain local or in an explicitly isolated test environment until the applicable external gates are completed and reviewed. Do not enable production response execution while the provider adapter boundary is empty. Keep the emergency kill switch enabled.

The repository's screenshots and demo video are derived from a local synthetic lab dataset. They demonstrate the user interface and workflows, not a live customer cloud account, successful cloud containment or production-grade detection accuracy.

## Evidence for a release candidate

Every release candidate should include:

- Source commit and version.
- CI run and full job conclusions.
- Test, coverage and dependency-audit outputs.
- Terraform and container build results.
- Configuration and secret-handling review.
- External provider/IdP/SMTP acceptance records, if in scope.
- Backup/restore, failover and load-test records, if in scope.
- Independent assessor report and remediation closure, if claiming security assurance.
- Rollback instructions, known limitations and operator ownership.
