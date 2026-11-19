# Release assurance and readiness checklist

## Offline local milestone

- [x] Unit/integration tests for API, evidence, detection, graph, mocked AWS and mocked Azure adapters.
- [x] Configurable API bearer roles, request limits, security headers and mutation audit records.
- [x] Versioned evidence manifest, provenance fields, integrity verifier and detached Ed25519 support.
- [x] Deterministic detection evaluation methodology, confidence rationale and fixture regression tests.
- [x] Automated SQLite online backup, manifest verification and non-overwriting restore commands, plus health/rollback runbooks.
- [x] Local-only container profile authored with non-root user, read-only root filesystem, dropped capabilities and loopback host port; Compose YAML parsed.
- [ ] Docker image build in CI (job configured; result pending).
- [x] AWS access disabled for this milestone; no live cloud calls or resources.
- [ ] Independent security review / penetration test.
- [ ] Actual backup restore exercise on a separately managed backup copy.
- [ ] Production telemetry and independently reviewed labels.

## Not approved for hosted production

The UI has no browser login/token lifecycle. The service remains single-tenant, loopback-bound and SQLite-backed. Role tokens are long-lived environment secrets with manual rotation; no MFA, SSO, expiry or revocation service exists. The audit table is local and mutable by host/database administrators. Rate limits are in-memory and per-process. Trusted timestamping, WORM storage, managed secret storage, central monitoring and tenant isolation are not implemented. A reverse proxy alone does not solve these gaps.

## External assurance gates

1. Independent threat-model review and penetration test, with findings tracked to closure.
2. Browser UI authentication and identity lifecycle, authorization boundaries and tenant isolation if multi-user.
3. Managed secrets, TLS ingress, central append-only audit, monitoring/alerting and operational ownership.
4. Verified backup/restore and incident-response exercise.
5. Representative telemetry evaluation and detection tuning.
6. Live AWS and Azure integration/inventory validation after active accounts, explicit provider-by-provider scope and cost approval.
7. Trusted timestamping / immutable evidence archive if required by the evidence policy.

## Support policy

This is a best-effort engineering lab, not a managed service or SLA-backed security product. Releases should include version, commit, supported Python/Node versions, test results, dependency audit results, known limitations and rollback instructions. Security issues should be reported privately to the repository maintainer rather than published with exploit details.


See `docs/PROVIDER_EXPANSION_REPORT.md` for the dual-provider implementation and latest local validation snapshot.
