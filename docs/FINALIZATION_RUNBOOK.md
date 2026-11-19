# Finalization runbook: Phases 15–20

**Status date:** 19 November 2026  
**Repository:** `TheRootBaba/CloudShield-Lab`  
**Purpose:** turn the remaining external release gates into bounded, repeatable work packages. This document does not mark those gates complete.

## 1. Current release decision

The offline implementation tranche for Phases 15–20 is merged. AWS and Azure adapters are implemented, opt-in, bounded and mock-tested. The local container profile and backup/restore tooling are present. The recorded CI run built the container image without pushing it and validated the Compose configuration.

**Current disposition: local engineering / portfolio release only. Not approved for LAN, internet-facing or hosted production use.**

The following have not been performed and must not be represented as passed:

- Live AWS or Azure account validation.
- Independent penetration test or threat-model review.
- Browser authentication/session lifecycle or tenant isolation.
- Production monitoring, alerting, load testing or incident-response exercise.
- Restore exercise against a separately managed backup.
- Trusted timestamp authority or immutable WORM archive integration.
- Detection accuracy measurement against representative independently labelled production telemetry.

## 2. Change-control and safety rules

Before any live provider test, record an approval containing:

1. Named operator and approver.
2. AWS account ID and regions, and/or Azure tenant and subscription ID.
3. Exact collector operation(s), time window, page/record caps and expected API request ceiling.
4. Confirmation that the identity is read-only and scoped only to the approved account/subscription.
5. A maximum spend/request boundary and the stop condition.
6. Test window and evidence retention location.

Do not paste credentials, client secrets, access tokens, private keys or full environment dumps into tickets, logs or chat. Authenticate locally using the provider's supported credential chain. Keep the AWS and Azure enable flags unset unless the corresponding test is approved. Do not apply either Terraform root as part of collector validation.

## 3. Phase 18 — live provider validation

### 3.1 AWS preflight

- Use a dedicated non-production account or isolated sandbox, not a personal/root identity.
- Use a named IAM role/profile with only the read actions documented by the AWS adapter. Review the current provider report and implementation before granting permissions; do not copy a broad managed policy without inspection.
- Confirm the approved account ID and explicit region list.
- Begin with one region, a short lookback, and the smallest supported page/record caps.
- Confirm CloudTrail event history is available and that the selected account/region has expected activity.
- Keep inventory and CloudTrail collection as separate test cases.

PowerShell setup (run locally, never commit the profile or credentials):

```powershell
python -m pip install -e ".[aws]"
aws sts get-caller-identity
$env:CLOUDSHIELD_ENABLE_AWS_COLLECTOR = "1"
# Start CloudShield and use its AWS CloudTrail collector for the approved region/window.
# For inventory, disable the collector flag and explicitly enable only the inventory flag:
Remove-Item Env:CLOUDSHIELD_ENABLE_AWS_COLLECTOR -ErrorAction SilentlyContinue
$env:CLOUDSHIELD_ENABLE_AWS_INVENTORY = "1"
cloudshield aws-inventory --regions us-east-1 --max-pages 1 --output artifacts/aws-inventory-validation.json
```

The example region is illustrative; replace it with an approved region. Do not run the inventory command until its exact IAM actions and request cap have been reviewed against the current source and provider report. The inventory is intentionally partial and must not be labelled a complete AWS account inventory.

### 3.2 Azure preflight

- Use a dedicated validation identity. Prefer a separate test subscription where possible.
- Scope read access to one subscription only.
- Intended minimum read actions are `Microsoft.Resources/subscriptions/resources/read` and `Microsoft.Insights/eventtypes/values/read`; validate effective permissions in the tenant before testing.
- Do not grant Owner, Contributor, write, delete or role-assignment permissions.
- Confirm the selected subscription and its expected Activity Log retention/window.
- Begin with a short lookback and low page/record caps.

PowerShell setup:

```powershell
python -m pip install -e ".[azure]"
az login
az account show
$env:AZURE_SUBSCRIPTION_ID = "<approved-subscription-id>"
$env:CLOUDSHIELD_ENABLE_AZURE_COLLECTION = "1"
cloudshield azure-inventory --max-pages 1 --max-records 100 --output artifacts/azure-inventory-validation.json
cloudshield azure-activity-logs --lookback-hours 1 --max-pages 1 --max-records 100 --output artifacts/azure-activity-validation.json
```

Replace the placeholder locally. Do not paste the subscription ID together with credentials or tokens into public issues. If the CLI does not accept a particular cap in the installed version, stop and consult `cloudshield <command> --help`; do not improvise a higher limit.

### 3.3 Acceptance criteria for each provider

A provider test is accepted only when all of the following are recorded:

- The observed identity and account/subscription match the approved scope.
- The collector refuses to run when its explicit enable flag is absent.
- A bounded request succeeds and reports provider, scope, window, pages, records, truncation, partial failures and operation completeness.
- A deliberately small page cap produces a truthful truncation/incompleteness signal when more data exists.
- A permission-denied or throttling case is safely reported; no partial result is mislabeled complete.
- Repeated continuation tokens terminate safely.
- No write, delete, role assignment, resource creation or remediation API is invoked.
- Output artifacts are reviewed for sensitive values and stored in the approved evidence location.
- Actual API calls, rate-limit behavior and any provider-side charges are recorded.

A successful one-subscription Azure test does not prove tenant-wide or management-group coverage. A successful AWS region test does not prove multi-region or organization-wide coverage.

## 4. Phase 16/19 — backup and restore exercise

Perform this only on a disposable local test database or an approved copy, never on the only production evidence database.

1. Stop writes or use a consistent test snapshot.
2. Create a backup with `cloudshield backup`.
3. Verify it with `cloudshield verify-backup`.
4. Copy the database and sidecar manifest to a separate directory or separately managed storage location.
5. Restore to a new destination path; do not overwrite the source.
6. Run `PRAGMA integrity_check` on the restored SQLite database.
7. Start CloudShield against the restored copy in an isolated local test process.
8. Compare expected event/finding/incident counts and verify a sample of evidence bundles.
9. Record elapsed time, backup size, restore size, operator, outcome and any data loss.
10. Preserve the original source and backup until the exercise is signed off.

The colocated SHA-256 manifest detects accidental corruption but is not an independent trust anchor if an attacker can change both files. Copy or sign the manifest independently. Do not claim immutable retention until an actual WORM/object-lock policy is configured and tested.

## 5. Phase 15 — application security work before any remote exposure

The existing API role tokens are not a complete browser authentication system. Before multi-user or hosted operation, design and independently review:

- OIDC login with a supported identity provider.
- Short-lived server-side sessions, secure/HttpOnly/SameSite cookies, CSRF defenses and logout.
- MFA and account recovery policy at the identity provider.
- Explicit server-side authorization checks on every API route and object access.
- Tenant isolation enforced in data access, not merely in the UI.
- Token/session expiry, rotation and revocation.
- Managed secret storage and TLS termination.
- Central append-only audit export, alerting and retention.
- Distributed rate limiting and abuse controls.
- Security headers/CSP review, dependency update policy and secret scanning.
- Independent penetration testing and closure of all critical/high findings.

Until that work is complete, preserve loopback-only binding and single-user SQLite operation. Do not use a reverse proxy or VPN as a substitute for application authentication and tenant isolation.

## 6. Phase 17 — representative detection evaluation

The 30-case fixture corpus is a regression suite, not production accuracy. To make an accuracy claim:

1. Define the telemetry sources and collection period before looking at results.
2. Sample representative benign and malicious/confirmed incident cases across supported event families.
3. Remove secrets and unnecessary personal data; preserve enough context for correct labelling.
4. Have two qualified reviewers label cases independently, then adjudicate disagreements.
5. Keep the labels and dataset version separate from the detection implementation.
6. Freeze the rule version and evaluation split before calculating metrics.
7. Report per-rule TP/FP/FN/TN, precision, recall, specificity, F1, sample sizes and confidence intervals.
8. Document class imbalance, missing telemetry, data-source coverage and known blind spots.
9. Tune on a development split; report final metrics only on a held-out set.
10. Do not use fixture-only or small-sample results as a production efficacy claim.

## 7. Phase 16 — trusted time and immutable evidence

If evidence policy requires trusted time or immutable retention, select a TSA and archive provider only after legal, cost, region and retention review. The target design is:

1. Canonicalize and hash the evidence bundle and manifest.
2. Sign the bundle with an independently controlled signing key.
3. Submit the digest to an RFC 3161-compatible TSA and retain the token plus validation chain.
4. Store the bundle, signature, public-key identity, TSA token and verification metadata in an immutable/WORM archive with retention lock.
5. Periodically verify signatures, timestamp chains, retention state and retrieval.
6. Test key rotation, revocation, archive expiry and legal hold procedures.

A timestamp proves that a digest existed by a time asserted by the TSA; it does not prove that source telemetry was true. Do not mark this gate complete based on design documentation alone.

## 8. Phase 20 — independent assurance and operational sign-off

Commission an independent reviewer with a defined scope covering the threat model, API authorization, local data handling, evidence integrity, cloud adapter permissions, dependency/supply-chain posture and container hardening. Require a written report, severity-ranked findings, remediation evidence and retest.

Before any production decision, also complete:

- Load/performance test with stated dataset size and resource limits.
- Backup restore and incident-response tabletop with named owners.
- Monitoring/alerting test including failure and provider throttling cases.
- Secret rotation and recovery exercise.
- Rollback rehearsal to a known-good build and database copy.
- Review of privacy, retention, support and vulnerability disclosure procedures.

## 9. Final sign-off record

Do not change a gate to complete until its evidence is linked here or in the release record.

| Gate | Owner | Evidence link / artifact | Status |
|---|---|---|---|
| AWS live validation | TBD | TBD | Blocked: approved AWS scope required |
| Azure live validation | TBD | TBD | Blocked: active subscription and approved scope required |
| Backup restore exercise | TBD | TBD | Not run |
| Browser auth and tenant isolation | TBD | TBD | Not implemented |
| Trusted timestamp / WORM | TBD | TBD | Design only |
| Representative detection evaluation | TBD | TBD | Production-labelled data required |
| Independent security review / penetration test | TBD | TBD | Reviewer required |
| Load and incident-response exercises | TBD | TBD | Not run |
| Hosted monitoring and operational ownership | TBD | TBD | Not configured |

## 10. References in this repository

- `docs/RELEASE_ASSURANCE.md`
- `docs/PROVIDER_EXPANSION_REPORT.md`
- `docs/AZURE_PROVIDER.md`
- `docs/DEPLOYMENT_OPERATIONS.md`
- `docs/SECURITY_THREAT_MODEL.md`
- `docs/TRUSTED_TIMESTAMPING.md`
- `docs/DETECTION_EVALUATION.md`

**Bottom line:** the offline implementation is delivered; the remaining items are real-world assurance and account-dependent validation. Keep the application local-only until the security and operational release gates are independently satisfied.
