# Current capabilities and release boundaries

CloudShield is a local-first cloud security engineering lab. This document describes the current codebase, not a certification or claim that every external integration has been accepted.

## Product capabilities

- React security command center for overview, incidents, detections, attack-path hypotheses, evidence, alerts, response controls, assets, cloud data sources and detection rules.
- Python API and deterministic event pipeline for selected AWS CloudTrail, AWS Security Hub and Azure Activity Log event shapes.
- Explainable rule findings with severity, source context and curated MITRE ATT&CK references.
- Incident grouping by actor/account and bounded time window; graph relationships are evidence-backed correlations, not proof of causality.
- SHA-256 evidence fingerprints, portable incident bundles and optional detached Ed25519 signatures.
- Local simulations and a labelled 40-case regression corpus covering 19 catalogued AWS/Azure rules.
- Workspace-isolated evidence databases and authenticated role-based access.
- AWS STS AssumeRole with unique ExternalId and Azure managed/workload identity configuration, with global provider-identity ownership reservation.
- Separate scheduled read-only collector worker, bounded polling, retry/backoff, partial inventory refresh, worker heartbeat and low-cardinality operational metrics.
- Deduplicated HIGH/CRITICAL alerts, in-app acknowledgement and optional STARTTLS email notifications.
- Response dry-run plans, blast-radius reporting, independent approval quorum, plan-digest binding, idempotency, audit history and a default-on emergency kill switch.
- Firebase sign-in integration points, TOTP enrollment/challenge client flows and configurable OIDC/SAML provider support.
- Local production Compose profile, HTTPS ingress template, backup/restore commands and opt-in offsite-backup Terraform.

## Hard boundaries

| Area | Current boundary |
|---|---|
| Detection | Selected control-plane patterns; not comprehensive threat detection |
| AWS collection | Bounded CloudTrail management-event history; not a streaming feed |
| Azure collection | Bounded subscription Activity Logs and selected ARM metadata |
| Inventory | Partial observed/resource metadata; not authoritative organization-wide inventory |
| Tenant storage | Per-workspace SQLite evidence stores |
| Worker coordination | SQLite leases on a supported shared volume; single-host design, not multi-region distributed coordination |
| Evidence | Hash integrity and optional signatures; not proof of source truth or trusted time |
| Response | Dry-run and approval orchestration implemented; no reviewed production AWS/Azure write adapter installed |
| Availability | Single-host deployment template; no HA/SLA claim |

## Verification snapshot

The Phase 23–26 implementation branch was locally verified with 188 Python tests, compilation, Bandit, the 40-case detection evaluation and the production dependency audit. GitHub Actions run #49 completed successfully with all four jobs passing: Python tests, Terraform, container build and web assets. See [the merged implementation PR](https://github.com/TheRootBaba/CloudShield-Lab/pull/13) and [its CI run](https://github.com/TheRootBaba/CloudShield-Lab/actions/runs/44648288567).

The evidence screenshots and redacted demo in the repository are recordings of the local application using a synthetic lab dataset. They are product walkthrough evidence, not evidence of a live customer cloud integration.

## External release gates

1. Validate AWS and Azure tenant binding and collection in dedicated isolated accounts.
2. Implement, independently review and test provider-specific response adapters, including real rollback/compensation.
3. Move worker coordination/jobs to PostgreSQL or a durable queue before multi-host operation.
4. Connect centralized logs, metrics, paging, SLOs and operational ownership; run load, failover and off-host restore drills.
5. Complete independent penetration testing and tenant-isolation assessment; resolve and retest findings.
6. Measure detection precision/recall on representative, independently labelled and privacy-reviewed telemetry.
7. Complete Firebase MFA/IdP policy setup and SMTP delivery testing where those integrations are required.

See [Cloud operations](CLOUD_OPERATIONS.md), [Architecture](ARCHITECTURE.md), [Release assurance](RELEASE_ASSURANCE.md) and [Phase 23–26 implementation report](PHASES_23_26_IMPLEMENTATION_REPORT.md).
