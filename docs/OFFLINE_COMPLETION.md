# Offline completion and handoff

**Verification date:** 19 November 2026
**Repository:** TheRootBaba/CloudShield-Lab
**Verified main baseline:** `0f2d35396c09d1c19c737fe70f3e230969c7798c`

## Scope decision

AWS validation is deferred. No AWS credentials were configured, no AWS API calls were made, and no AWS resources were created, modified or deleted during this completion pass. This preserves the stated $0 cloud-cost ceiling. AWS account activation, CloudTrail collection and live inventory are not prerequisites for using the offline lab.

## Completed offline capabilities

- CloudTrail and Security Hub event normalization and selected explainable detection rules.
- Offline synthetic event scenarios with synthetic provenance.
- Incident grouping, event/resource relationship views and bounded non-causal temporal correlation.
- Local SQLite evidence storage, incident workflow and portable evidence bundles.
- SHA-256 integrity checks and optional encrypted Ed25519 detached signatures.
- Curated fixture evaluation harness and bounded, opt-in AWS adapters tested with mocks only.
- Loopback-only API binding and local React command center.
- Separate opt-in secure and intentionally vulnerable Terraform examples.

## Verification performed on 19 November 2026

| Check | Result |
|---|---|
| Python unit/integration suite | 73 tests passed |
| Python compile check | Passed |
| Detection evaluation corpus | 26/26 fixture cases passed; not production accuracy |
| React/Vite production build | Passed |
| Terraform formatting check | Passed |
| Terraform secure root validation | Passed |
| Terraform vulnerable training root validation | Passed |
| Git whitespace/diff check | Passed |

The Vite build refreshed the tracked generated files under `web/`. No application source-code changes were needed during this final verification pass.

## Remaining external gates

These are intentionally not marked complete:

1. **Live AWS validation:** requires an active isolated account, least-privilege identity and a separately agreed cost boundary. No live calls were attempted.
2. **Production detection quality:** requires representative telemetry and independently reviewed labels.
3. **Authoritative cloud inventory:** current inventory is deliberately partial and bounded; organization-wide and multi-service enumeration is not implemented.
4. **Hosted/multi-user operation:** authentication, authorization, tenant isolation, CSRF controls, rate limiting, audit controls, secret management and deployment hardening are still required. Keep the app on loopback.
5. **Trusted evidence time and custody:** external trusted timestamping or immutable evidence storage is not implemented.
6. **Causal attack-path claims:** current graph edges are explainable correlations, not proof of causation or effective reachability.

## Local start

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
python -m cloudshield.api
```

Open http://127.0.0.1:8765 and use **Run simulation** for offline synthetic data. The simulation does not contact AWS.

## Safety boundary

Do not enable the AWS collector or inventory commands as part of this $0-cost offline setup. Do not apply either Terraform root. The vulnerable Terraform root is a deliberately insecure training fixture and must never be applied to a production or shared account.


## Follow-up dual-provider and operations extension

See `docs/PROVIDER_EXPANSION_REPORT.md` for Azure adapter support, AWS resilience improvements, backup/restore tooling, local container profile and the remaining live-validation gates.
