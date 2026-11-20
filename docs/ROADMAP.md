# Current status superseding historical roadmap snapshots ? 19 November 2026

The historical checklist below records prior phase work and contains older single-user/provider-gating statements. For current Phase 21 implementation status, read [NEXT_PHASES_DELIVERY_REPORT.md](NEXT_PHASES_DELIVERY_REPORT.md) and [CLOUD_OPERATIONS.md](CLOUD_OPERATIONS.md). The current branch has workspace-scoped AWS/Azure identity configuration, a separate scheduled collector worker, persistent bounded inventory, HIGH/CRITICAL alerting with optional SMTP, independently approved response requests, Firebase TOTP/SSO client flows, readiness heartbeat and an opt-in S3 Object Lock backup Terraform root. Live cloud/SMTP/IdP/backup execution and independent assurance remain external release gates; response write actions are not implemented.

---

# Delivery roadmap and progress

CloudShield Lab is a local-first defensive engineering lab. A checked item means the implementation and local automated checks exist; it does not imply production readiness or live-cloud validation.

## Phase 1 â€” detection engine
- [x] Normalize CloudTrail records and Security Hub finding envelopes.
- [x] Preserve source payload, account, region, actor, resources and request/response context.
- [x] Add selected IAM, S3, EC2/network, CloudTrail, KMS, Lambda, RDS and root-login event-pattern rules.
- [x] Explain findings with rule IDs, severity, rationale and source evidence.
- [x] Maintain an explicit detection rule inventory and coverage limitations.

## Phase 2 â€” infrastructure
- [x] Separate secure and intentionally vulnerable Terraform roots.
- [x] Secure baseline includes encryption, versioning, public-access blocks, CloudTrail and Security Hub when explicitly enabled.
- [x] Vulnerable training root remains intentionally insecure and opt-in.
- [x] Both roots default to zero resource creation.
- [x] Terraform formatting and configuration validation are part of CI.

## Phase 3 â€” attack simulation
- [x] Offline synthetic IAM, public S3 and public SSH scenarios.
- [x] Add a multi-step synthetic sequence: privilege mutation, credential creation, CloudTrail disruption and exposed admin ingress.
- [x] Mark synthetic event provenance in normalized evidence.
- [x] Confirm zero cloud API calls from the simulator.

## Phase 4 â€” analytics and evidence
- [x] Correlate findings by actor/account and time window.
- [x] Produce deterministic incidents and chronological timelines.
- [x] Build explainable event, actor, account and resource relationship graphs.
- [x] Harden incident correlation graph: evidence-backed sequence hypotheses, 24-hour bound, duplicate-ID handling and explicit non-causal semantics (Phase 14 offline hardening).
- [x] Persist events, findings and incidents in SQLite with idempotent ingestion.
- [x] Preserve SHA-256 fingerprints and expose event-level evidence retrieval.

## Phase 5 â€” analyst command center
- [x] Responsive React security command center.
- [x] Overview, incidents, detections, attack paths, evidence vault, data sources and rule library views.
- [x] Search/filter, incident drill-down, evidence inspection, JSON import and simulation controls.
- [x] Local HTTP API backed by the detection and evidence domain logic.
- [x] White-first responsive visual system, desktop/mobile navigation and event-derived analytics.

## Phase 6 â€” optional live AWS ingestion
- [x] Opt-in one-shot read-only CloudTrail LookupEvents adapter.
- [x] Region and lookback limits, page limit, and no polling.
- [x] Collector disabled by default and uses the standard AWS credential chain.
- [ ] Validate against a real, isolated AWS account with least-privilege permissions and explicit cost approval.

## Phase 7 â€” detection validation and ATT&CK alignment
- [x] Curated ATT&CK references for selected detection rules.
- [x] Positive, negative, adversarial and mapping-integrity tests.
- [x] Deterministic labelled fixture corpus and per-rule precision/recall/specificity/F1 calculation (Phase 11).
- [ ] Production false-positive / false-negative rates from representative labelled telemetry.

## Phase 8 â€” observed asset inventory
- [x] Event-derived inventory and common AWS resource classification.
- [x] First/last observed, actor/account/region, event counts and finding associations.
- [x] Inventory and relationship graph API and React view.
- [x] Optional bounded read-only live inventory for selected EC2, security-group, S3 bucket-name and IAM principal metadata (Phase 13).
- [ ] Full authoritative inventory across all AWS services and organization accounts.

## Phase 9 â€” incident response workflow
- [x] Status transitions, priority, assignment and analyst notes per incident.
- [x] Persisted workflow state and activity history in SQLite.
- [x] Validate transitions and input lengths; unknown incidents return 404.
- [x] Workflow controls in incident investigation panel.
- [x] Workflow unit/API tests.

## Phase 10 â€” portable evidence bundle and integrity verifier
- [x] Export incident, referenced events, findings, workflow state/history and SHA-256 hashes as JSON.
- [x] Bundle manifest digest and counts.
- [x] Verify incident/event/finding digests, manifest and timeline-to-event references.
- [x] Export from incident view; verify bundle from Evidence Vault.
- [x] Tamper detection, malformed bundle and reference consistency tests.
- [x] Optional detached Ed25519 signatures with encrypted private keys and external public-key verification (Phase 12).
- [ ] Trusted timestamping or immutable external chain of custody.

## Phase 11 â€” detection evaluation harness
- [x] Hand-labelled positive and negative event corpus covering all 13 catalogued rules.
- [x] Per-rule and micro-averaged confusion counts, precision, recall, specificity and F1.
- [x] CLI report generation and regression tests.
- [x] Clearly label fixture-only metrics; no production accuracy claims.

## Phase 12 â€” signed evidence bundles
- [x] Encrypted Ed25519 private-key generation and public-key export.
- [x] Refuse to sign invalid evidence bundles.
- [x] Detached signature creation and verification against an independently supplied public key.
- [x] Reject tampering, wrong keys and malformed signatures.
- [x] Optional dependency isolated in the signing extra.

## Phase 13 â€” bounded AWS inventory
- [x] Explicit opt-in only; disabled by default.
- [x] Read-only EC2 instances/security groups, S3 bucket names, IAM roles/users.
- [x] Explicit region list, maximum five regions, maximum two pages per operation.
- [x] Report API-call count, truncation and exact IAM permissions.
- [x] Offline mocked tests; no AWS credentials or API calls used in validation.
- [ ] Real isolated-account validation after explicit account and cost approval.

## Verification snapshot â€” 18 November 2026
- 73 Python unit/integration tests pass after Phase 14 offline hardening; Python compilation succeeds.
- 26/26 labelled detection fixture cases pass (fixture-only metrics, not production accuracy).
- Ed25519 signature/key tests pass, including tamper, wrong-key and sidecar overwrite rejection.
- AWS inventory adapter tests pass with mocked clients; no AWS network calls were made.
- Vite production build passes with lazy-loaded chart chunking: main 407.27 kB and overview 471.22 kB (gzip 130.14 kB and 132.19 kB); no chunk-size warning.
- Desktop (1440px) and mobile (390px) browser smoke tests pass; no console/page errors. Incident workflow and evidence export/verification smoke tests pass.
- Terraform formatting and both root validations pass.
- npm audit --omit=dev reports 0 production vulnerabilities. The full development audit still returns five high findings associated with picomatch; the GitHub advisory page now marks the underlying advisory withdrawn. No forced downgrade was applied.

## Remaining gates â€” not safe to mark complete without external prerequisites
- [ ] Real AWS sandbox validation of CloudTrail and inventory using a dedicated account, least-privilege role and approved cost boundary.
- [ ] Broader inventory (VPCs, subnets, load balancers, RDS, Lambda, KMS, EBS, policies/configuration) and organization-account discovery.
- [ ] Representative production detection tuning and measured false-positive/false-negative rates.
- [x] Core browser authentication, server-side roles, CSRF, invitation-only multi-user workspaces, rate limits and local auth audit. Separate HTTPS production profile is authored; enterprise identity and external assurance remain open.
- [ ] Independent trusted timestamping or immutable evidence storage.
- [ ] Full causal attack-path analysis only after trustworthy identity, network and resource relationship data exists. Current Phase 14 graph is correlation-only; see `docs/ATTACK_PATH_CORRELATION.md`.

## Current safety boundary (supersedes the historical note above)
The local app binds to 127.0.0.1 by default and uses Firebase-backed multi-user authentication with workspace-isolated evidence databases. AWS/Azure connections are workspace-scoped, disabled until tested and explicitly enabled, and collection is read-only and bounded. Synthetic scenarios never execute attacks. Guided response requests require a separate administrator decision, but execution remains fail-closed; no cloud write/remediation API is implemented. CloudShield is not a production-certified CSPM/SIEM/SOAR, and the external acceptance gates in the Phase 21 delivery report remain open.


## Offline verification refresh — 19 November 2026

- [x] Re-ran all 73 Python unit/integration tests successfully.
- [x] Python compile check passed.
- [x] Re-ran the curated detection corpus: 26/26 fixture cases passed; this is not production accuracy.
- [x] React/Vite production build passed.
- [x] Terraform recursive formatting check passed.
- [x] Secure and vulnerable Terraform roots both passed terraform validate using their existing local provider initialization.
- [x] git diff check passed.
- [ ] Live AWS validation remains deferred; no AWS calls or resource changes were made, preserving the zero-dollar cloud-cost boundary.
- [ ] Production telemetry, hosted multi-user security, trusted timestamping and authoritative organization-wide inventory remain external gates.

See OFFLINE_COMPLETION.md for the handoff and local start instructions.


## Phases 15?20 ? offline tranche (19 November 2026)

### Phase 15 ? API security controls
- [x] Optional role-specific bearer-token authentication and analyst/responder/admin authorization for API routes.
- [x] 32-character minimum unique tokens, constant-time comparison and fail-closed token configuration.
- [x] Per-IP in-memory request limits, strict JSON object/content-type/length validation and 2 MiB cap.
- [x] Cross-origin Origin rejection for writes and restrictive security response headers.
- [x] SQLite mutation audit entries for workflow, notes, ingest, simulation and AWS collector invocation.
- [x] Threat model and explicit residual-risk/deployment boundary.
- [x] Browser login, 12-hour revocable sessions, tenant database isolation and invitation workflows.
- [ ] MFA/SSO, verified email, password recovery, distributed rate limiting, independent tenant-isolation review and penetration test.

### Phase 16 ? evidence custody
- [x] Versioned bundle v1.1, producer/export metadata, collection scope and source-format provenance.
- [x] Strict bundle version/provenance/count/reference checks and existing digest/tamper tests.
- [x] Detached Ed25519 signature and independently trusted public-key verification.
- [x] Key rotation, retention/deletion and external verification procedure documented.
- [ ] Trusted timestamping, immutable WORM archive and externally managed key registry.

### Phase 17 ? detection quality
- [x] 26-case labelled fixture corpus and deterministic per-rule/micro metrics.
- [x] Explicit confidence tier and rationale on findings; documented severity/confidence semantics.
- [x] Regression coverage for duplicate IDs, malformed/missing timestamps, out-of-order timelines and adversarial private/denied cases.
- [x] Real-world independent label-review methodology documented.
- [ ] Representative production labels, statistically meaningful performance and calibrated confidence remain external gates.

### Phase 18 ? cloud integrations (deferred)
- [x] Provider adapter contract documents bounded pagination, retry/backoff, throttling, partial failure, provenance and least-privilege requirements.
- [x] Existing AWS adapters remain opt-in and mock-tested.
- [ ] Live CloudTrail/Security Hub and multi-region/organization validation intentionally deferred until active account and separately approved cost boundary. No AWS calls made in this tranche.

### Phase 19 ? operations design
- [x] Local build/run configuration, secret guidance, health/logging, backup/restore, rollback and recovery runbooks documented.
- [ ] Production container/hosted deployment, central monitoring/alerting and exercised backup restore deferred; current UI has no login lifecycle and app remains single-tenant/loopback-only.

### Phase 20 ? assurance preparation
- [x] Release checklist, risk register, known limitations and support policy documented.
- [ ] Independent security review/penetration test, production load test, backup restore and incident-response exercises require external environment and reviewers.

See `docs/PHASES_15_20_REPORT.md` for the exact delivery status and `docs/RELEASE_ASSURANCE.md` for release gates. A checked offline item is not a claim of hosted production readiness.


## Provider and operations extension ? 19 November 2026

- [x] Add Microsoft Azure as a second selectable provider alongside AWS.
- [x] Add bounded read-only Azure ARM inventory and subscription Activity Log collection using `DefaultAzureCredential`.
- [x] Add Azure Activity Log normalization and conservative RBAC/diagnostic-settings detections with regression fixtures.
- [x] Add provider status endpoint, explicit enable flag, admin-only API collection routes and CLI commands.
- [x] Harden AWS continuation-token handling, standard retry configuration and partial-failure reporting.
- [x] Add automated SQLite online backup, SHA-256 manifest verification and non-overwriting restore CLI.
- [x] Add a local-only hardened Docker Compose profile and CI container-build job.
- [x] Document optional RFC 3161 trusted timestamping and WORM archive design.
- [ ] Live AWS/Azure validation remains dependent on active accounts, least-privilege credentials and separately approved API/cost boundaries.
- [ ] MFA/SSO, email verification, password recovery, independent penetration test, hosted monitoring, production load test, provider tenant identities and production-host restore exercise remain external release gates.

See `docs/PROVIDER_EXPANSION_REPORT.md` for implementation detail and exact verification results.
