# CloudShield Lab â€” delivery report

**Report date:** 19 November 2026
**Repository:** TheRootBaba/CloudShield-Lab
**Baseline:** main at merge commit `386e60bee116ed357b6144408b405339c4634e15`

## Executive summary

Phases 11â€“13 have been implemented on top of the merged Phase 1â€“10 baseline. The project now includes a deterministic detection evaluation harness, optional detached Ed25519 evidence signatures, a bounded opt-in read-only AWS inventory command, and lazy-loaded analytics charts. Local automated tests and browser checks pass.

This is not a production cloud security platform. Real AWS validation, production detection accuracy measurement, full organization-wide inventory, hosted authentication/authorization and independent trusted timestamping remain explicit external gates.

## Delivered in this tranche

### Phase 11 â€” detection evaluation
- Added 26 hand-labelled positive and negative event-shape fixtures covering all 13 catalogued rules.
- Added per-rule and micro-averaged TP/FP/FN/TN, precision, recall, specificity and F1.
- Added CLI command: `cloudshield evaluate fixtures/detection_evaluation.json`.
- Current fixture result: 26/26 cases pass; micro precision, recall, specificity and F1 are each 1.0000.
- Interpretation: fixture-only regression result. It is not a measured production detection rate.

### Phase 12 â€” signed evidence
- Added password-encrypted Ed25519 private-key generation and PEM public-key export.
- Added detached signature sidecars for valid Phase 10 evidence bundles.
- Verification requires a separately supplied public key and checks its fingerprint, bundle digest and signature.
- Invalid/tampered bundles, wrong keys and overwriting an existing signature sidecar are rejected.
- The signing dependency is optional: `python -m pip install -e ".[signing]"`.

### Phase 13 â€” bounded AWS inventory
- Added explicit opt-in CLI inventory for EC2 instances, security groups, S3 bucket names, IAM roles and IAM users.
- Requires `CLOUDSHIELD_ENABLE_AWS_INVENTORY=1`, 1â€“5 explicit regions and a maximum of two pages per operation.
- Uses only `DescribeInstances`, `DescribeSecurityGroups`, `ListAllMyBuckets`, `ListRoles` and `ListUsers`.
- Includes API-call count, truncation status and required IAM actions in the output.
- Unit tests use fake clients. No AWS credentials were used and no AWS API requests were made.

### Frontend performance
- Extracted the overview analytics into a lazy-loaded React chunk.
- Production build now emits a 407.27 kB main JS chunk (130.14 kB gzip) and a 471.22 kB overview chunk (132.19 kB gzip).
- The previous single 877 kB chunk warning is eliminated; charts load when the overview is requested.

## Verification results

| Check | Result |
|---|---|
| Python compilation | Passed |
| Python unit/integration suite | 73 tests passed |
| Detection evaluation | 26/26 cases passed |
| Ed25519 signing tests | Passed, including tamper and wrong-key rejection |
| AWS inventory tests | Passed with mocked clients only |
| React production build | Passed; lazy chunks emitted without size warning |
| Desktop browser smoke | Passed at 1440px |
| Mobile browser smoke | Passed at 390px; no horizontal overflow |
| Browser console/page errors | None observed |
| Incident workflow and evidence smoke | Save status, add note, export/verify and vault upload verification passed |
| Terraform format | Passed |
| Terraform secure root validation | Passed |
| Terraform vulnerable training root validation | Passed |
| npm production dependency audit | 0 vulnerabilities |
| Full npm development-tree audit | 5 high findings still returned by npm audit, all linked to the picomatch advisory; GitHub's advisory page now marks that advisory withdrawn on 18 Nov 2026. No forced Vite downgrade or untrusted fork was applied. |

## Remaining gates

1. **AWS sandbox validation:** Requires a dedicated isolated AWS account/profile, least-privilege role, explicit region scope and cost approval. No live collection or inventory run was performed.
2. **Detection quality:** Requires independently labelled representative CloudTrail/Security Hub telemetry and human-reviewed ground truth before production false-positive/false-negative rates can be measured.
3. **Inventory coverage:** Current live inventory is partial metadata discovery. It does not enumerate all AWS services or Organizations accounts, inspect S3 objects/configuration, or evaluate effective permissions.
4. **Production/shared deployment:** Authentication, authorization, CSRF protection, rate limits, secret management, audit controls and deployment hardening must be added before any LAN, reverse-proxy or hosted exposure. Keep the server bound to 127.0.0.1.
5. **Evidence trust:** Ed25519 signatures authenticate the holder of a trusted signing key; they do not prove source telemetry truth, provide a trusted timestamp or create immutable storage.

## Useful commands

```powershell
# Run all tests
python -m unittest discover -s tests -v

# Reproduce fixture evaluation
cloudshield evaluate fixtures/detection_evaluation.json --output artifacts/detection-evaluation-report.json

# Generate a signing key pair (prompts for a password)
cloudshield keygen --private-key artifacts/cloudshield-signing-private.pem --public-key artifacts/cloudshield-signing-public.pem

# Sign and verify an exported Phase 10 evidence bundle
cloudshield sign-bundle artifacts/incident-evidence.json --private-key artifacts/cloudshield-signing-private.pem
cloudshield verify-signature artifacts/incident-evidence.json --public-key artifacts/cloudshield-signing-public.pem

# Optional AWS inventory: deliberately opt in first
python -m pip install -e ".[aws]"
$env:CLOUDSHIELD_ENABLE_AWS_INVENTORY="1"
cloudshield aws-inventory --regions us-east-1 --max-pages 1 --output artifacts/aws-inventory.json
```


## Offline handoff update — 19 November 2026

AWS validation has been explicitly deferred. No AWS credentials or API calls were used and no cloud resources were changed. A fresh local verification passed: 73 Python tests, Python compilation, 26/26 curated fixture cases, Vite production build, Terraform formatting, both Terraform root validations, and git diff check. See OFFLINE_COMPLETION.md for scope and remaining gates.
