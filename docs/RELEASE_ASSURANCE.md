# Release assurance and readiness checklist

## Offline local milestone

- [x] Unit/integration tests for API, evidence, detection, graph, mocked AWS and mocked Azure adapters.
- [x] Configurable API bearer roles plus multi-user browser login, scrypt password hashing, invitation-only workspaces, separate tenant databases, expiring/revocable sessions, CSRF protection, role enforcement, first-admin bootstrap-key protection and authentication audit records.
- [x] Versioned evidence manifest, provenance fields, integrity verifier and detached Ed25519 support.
- [x] Deterministic detection evaluation methodology, confidence rationale and fixture regression tests.
- [x] Automated SQLite online backup, manifest verification and non-overwriting restore commands, plus multi-workspace auth+tenant archive, verification, safe restore and recovery tests.
- [x] Local-only container profile and separate Caddy HTTPS production Compose profile authored; app is on an internal-only backend network with no published port/direct egress, Caddy alone is public ingress, and bootstrap secret is passed only to the app. Compose topology assertions pass.
- [x] Previous GitHub Actions run #33 built the local container image without pushing. Current production Compose validation is added to CI; a new build is pending.
- [x] AWS access disabled for this milestone; no live cloud calls or resources.
- [ ] Independent security review / penetration test.
- [x] Automated workspace-set backup/verify/restore exercise with restored-session authentication and tenant evidence checks; Windows deployment, quiesced backup and isolated restore-drill scripts are provided.
- [ ] Restore exercise on the actual production host using independently stored off-host media.
- [ ] Production telemetry and independently reviewed labels.
- [x] Local verification snapshot: 121 tests, 96% auth/recovery statement coverage (90% CI gate), 30/30 curated detection fixtures, Bandit zero findings, pinned cloud dependency lock audit clean, npm production audit clean, and production Compose topology checks passed. Whole-package branch-inclusive coverage is 79%; the 90% gate is not currently global.

## Not approved for hosted production

Core browser password/session authentication and workspace-level database isolation are implemented behind CLOUDSHIELD_AUTH_MODE=multi_user. The production Compose profile provides Caddy HTTPS ingress, an internal-only API network, Secure cookies and first-admin bootstrap protection, but it has not been deployed to a real host/domain. A guarded Windows deployment script validates config/build/start and internal plus public HTTPS health. The app is a single-host deployment template, not an HA SaaS service.

MFA/WebAuthn, OIDC/SAML SSO, verified email, password reset, session/device management UI, distributed rate limiting, external audit export, managed secret storage, monitoring/alerting, provider-specific tenant credentials and independent penetration testing remain open. Automated recovery tests pass locally, but an actual off-host production restore exercise remains open. The local Docker daemon was unavailable for a local image build; CI is configured to build and validate both Compose profiles.

## Support policy

This is a best-effort engineering lab, not a managed service or SLA-backed security product. Releases should include version, commit, supported Python/Node versions, test results, dependency audit results, known limitations and rollback instructions. Security issues should be reported privately to the repository maintainer rather than published with exploit details.


See `docs/PROVIDER_EXPANSION_REPORT.md` for the dual-provider implementation and latest local validation snapshot.
