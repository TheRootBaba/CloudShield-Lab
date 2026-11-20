# CloudShield current product capabilities

**Reviewed:** 19 November 2026  
**Build:** Firebase multi-user branch, local Docker deployment  
**Purpose:** Explain what the current product can do, what the empty dashboard means, and what remains before hosted production use.

## Product in one sentence

CloudShield Lab is a local-first cloud security investigation workbench: it ingests selected AWS/Azure audit exports, normalizes events, runs a curated set of explainable detections, correlates findings into investigation candidates, and preserves evidence and analyst workflow history.

It is a security engineering lab and portfolio project. It is not a complete CSPM, SIEM, EDR, SOAR, cloud-native threat detection service, or a substitute for GuardDuty, Security Hub, Defender for Cloud, or a managed SOC.

## What works in the current build

| Area | Current capability |
|---|---|
| Identity | Firebase email/password sign-up and sign-in, email verification, password-reset email, server-verified Firebase ID tokens, CloudShield session cookies and CSRF protection. |
| Authorization | Server-side admin, responder and analyst roles; single-use workspace invitations; member disable/revocation; isolated SQLite evidence databases per workspace. |
| Ingestion | User-initiated JSON import for supported CloudTrail, Security Hub, Azure Activity Log and EventBridge-shaped records. |
| Detection | Curated rules for selected IAM, S3, EC2/network, CloudTrail, KMS, Lambda, RDS and Azure control-plane patterns. Findings include rationale, severity/confidence metadata and selected ATT&CK references. |
| Incidents | Actor/account/time-window correlation into investigation candidates; incident details, timeline, workflow status, priority, assignee and append-only analyst notes. |
| Relationships | Event/resource relationship context and bounded sequence hypotheses. These are investigative leads, not proof of causality. |
| Asset view | Resource identifiers and relationships inferred from observed events. This is not authoritative live cloud inventory. |
| Evidence | SHA-256 record fingerprints, portable incident bundles, manifest/reference verification, optional Ed25519 detached signatures. |
| Evaluation | Deterministic labelled fixture corpus and per-rule evaluation metrics. Fixture performance is not production detection accuracy. |
| Offline lab | Synthetic scenarios, including a multi-stage sequence. They generate fake CloudTrail-shaped data locally and make zero AWS/Azure API calls. |
| Operations | Docker Compose, Caddy HTTPS ingress, non-root/read-only application container, SQLite backup/restore tooling and recovery documentation. |

## First-run workflow

1. Sign in with a verified Firebase account. The first verified identity becomes the initial administrator when the CloudShield auth store is empty and the bootstrap key is valid.
2. On the Overview page, choose an offline scenario and run it, or import a supported JSON export.
3. Open Detections to review matched rules and their rationale.
4. Open Incidents and select a case to inspect the timeline, update status/priority/assignee, and add analyst notes.
5. Export the incident evidence bundle and verify it in the Evidence Vault.
6. Review observed resource identifiers in Asset Inventory and the evidence-backed relationship context in Attack Paths.

An empty dashboard is the expected state before telemetry is imported or a simulation is run. It does not mean that CloudShield has discovered zero vulnerabilities in a live cloud account; no live provider scan is being run in the current shared Firebase deployment.

## Cloud provider boundary

- AWS CloudTrail LookupEvents, bounded AWS metadata inventory and Azure Activity Log/ARM adapters exist as opt-in, read-only integration code.
- In the current shared multi-user/Firebase deployment, live AWS/Azure collection is intentionally blocked until provider identities are tenant-scoped. Do not put one shared cloud credential into a multi-tenant service.
- AWS Security Hub and Azure Activity Log exports can be imported manually.
- No cloud resource creation, modification, remediation or deletion is performed by the offline simulator or normal import workflow.
- Live provider use requires real accounts, least-privilege tenant-specific identities, explicit enablement, cost/permission review and live integration tests.

## What is not implemented or not yet assured

- MFA and enterprise SAML/OIDC SSO.
- Automated invitation email delivery, managed SMTP and polished user/device/session administration.
- Tenant-scoped AWS/Azure identities and live provider collection from the multi-user UI.
- Continuous event streaming, scheduled polling, organization-wide resource inventory, data-plane coverage or real-time alert delivery.
- Automated remediation/playbooks or cloud write actions.
- External monitoring/alerting, centralized immutable audit export, managed secrets, off-host backup ownership and tested disaster recovery on the production host.
- Independent penetration test, production load/performance test, and operational incident-response exercise.
- Trusted timestamp authority/WORM evidence archive and external trust registry for signing keys.
- Calibrated real-world detection precision/recall. The fixture corpus only verifies expected behavior on its curated examples.

## Why browser console messages appear

- GET /api/auth/me returning 401 before sign-in is normal: no CloudShield session cookie exists yet. After successful sign-in, the same endpoint should return the current user.
- Firebase accounts:signUp HTTP 400 is a Firebase Authentication error response, not enough information by itself to diagnose. Inspect the response JSON error.message or the Firebase SDK error code shown in the form. Common codes include EMAIL_EXISTS / auth/email-already-in-use, WEAK_PASSWORD / auth/weak-password, INVALID_EMAIL / auth/invalid-email, OPERATION_NOT_ALLOWED / auth/operation-not-allowed, and TOO_MANY_ATTEMPTS_TRY_LATER / auth/too-many-requests.
- If the account was already created but verification email delivery failed, do not keep trying to create it again. Switch to sign-in, use the same email/password, and follow the verification resend message. Use Forgot password only if you need to reset the password.
- The browser's nested-form warning is a frontend/extension diagnostic and is not the cause of a Firebase 400 or an unauthenticated 401.

## Release posture

The local application, Firebase identity integration, and offline investigation workflow can be exercised on the development machine. This is not a public production launch. Before any external exposure, complete the remaining controls above, confirm CI and dependency audits, configure a real domain/TLS and firewall, restrict egress, test off-host backups/restores, and obtain independent security review.

See also:
- [Firebase authentication guide](FIREBASE_AUTH.md)
- [Deployment and operations](DEPLOYMENT_OPERATIONS.md)
- [Detection coverage](DETECTION_COVERAGE.md)
- [Release assurance gates](RELEASE_ASSURANCE.md)
- [Roadmap](ROADMAP.md)


## Phase 21 implementation addendum ? 19 November 2026

The current branch adds the following software capabilities beyond the earlier snapshot above:

- **Workspace-scoped cloud identities:** AWS role ARN + unique ExternalId with STS AssumeRole; Azure tenant/subscription + explicit managed/workload identity client ID. A global registry prevents the same identity tuple from being bound to multiple workspaces. Provider connections are disabled until an administrator successfully tests them.
- **Scheduled read-only collection:** a separate Docker worker polls enabled workspaces (default 5 minutes, configurable 1?60 minutes), uses bounded lookback/page counts and standard SDK retries, and refreshes limited inventory every six hours. Provider status and worker heartbeat are visible in Data Sources.
- **Live inventory persistence:** AWS selected EC2/security-group/S3-name/IAM metadata and Azure bounded ARM resource metadata are stored per workspace. This remains incomplete inventory, not organization-wide authoritative discovery.
- **Alerting:** new HIGH/CRITICAL findings create deduplicated workspace alerts. Active workspace admins/responders can receive optional authenticated STARTTLS email notifications; in-app alerts work without SMTP.
- **Response approvals:** finding-specific containment guidance can be requested by a responder and must be approved/rejected by a different workspace administrator. Decisions are audited. Approval does not execute cloud writes; execution is intentionally disabled.
- **Identity integrations:** Firebase TOTP enrollment and second-factor challenge handling plus one configured Firebase OIDC/SAML provider flow are implemented. Firebase Identity Platform enforcement, IdP metadata and domain configuration remain operator prerequisites.
- **Operations groundwork:** readiness endpoint includes a worker heartbeat; production Compose includes a separate worker service. An optional Terraform S3 backup root, offsite upload script and isolated restore-drill script are included.

### Phase 21 boundaries not yet externally verified

No live AWS/Azure tenant connection was available during implementation. No cloud infrastructure was applied. No SMTP delivery, Firebase TOTP enrollment/SSO provider, S3 Object Lock upload, offsite restore drill, centralized monitoring deployment, production load test or independent penetration test has been performed. Guided response execution is not implemented. See `docs/NEXT_PHASES_DELIVERY_REPORT.md` and `docs/CLOUD_OPERATIONS.md` for the complete status and operator steps.
