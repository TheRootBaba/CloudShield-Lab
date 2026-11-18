# Delivery status — local end-to-end core

## Phase 1 — detection engine
- [x] Normalize CloudTrail event records and Security Hub finding envelopes into a stable typed model.
- [x] Preserve source payload, account, region, actor, resources and request/response context.
- [x] Detect IAM policy mutations, public S3 bucket policy grants and public SSH/RDP/all-protocol ingress.
- [x] Explain findings with rule IDs, severity, rationale and source evidence.
- [x] Investigate individual events and return canonical SHA-256 evidence fingerprints.

## Phase 2 — infrastructure
- [x] Separate secure and intentionally vulnerable Terraform roots.
- [x] Secure baseline provisions (when explicitly enabled) an encrypted, versioned, non-public evidence bucket, multi-region CloudTrail and Security Hub.
- [x] Vulnerable lab provisions (when explicitly enabled) intentionally public S3 access and public SSH ingress.
- [x] Both roots default to zero resource creation.
- [x] Terraform formatting and configuration validation run locally and in GitHub Actions.

## Phase 3 — attack simulation
- [x] Offline synthetic IAM privilege-policy, public S3 and public SSH scenarios.
- [x] Deterministic scenario fixtures and repeatable timestamps for tests.
- [x] End-to-end assertions that each scenario generates the expected detection and incident.
- [x] Explicit simulator metadata confirms zero cloud API calls.

## Phase 4 — security analytics
- [x] Correlate findings by actor/account within a configurable time window.
- [x] Produce deterministic incident IDs and chronological investigation timelines.
- [x] Preserve event, finding and incident evidence with SHA-256 integrity fingerprints.
- [x] Persist events, findings and incidents in SQLite with idempotent ingestion.
- [x] Retrieve filtered timelines and individual persisted incidents.

## Verification completed
- 22 Python unit/integration tests pass on the local Windows environment.
- Editable package installation succeeds.
- Python bytecode compilation succeeds.
- Both Terraform roots pass `terraform validate`.
- Terraform formatting check succeeds.
- CLI workflow tested end to end: simulate -> analyze/store -> timeline -> retrieve incident.
- No AWS resources were created or modified.

## Scope and limitations
This is a local-first engineering lab, not a production CSPM/SIEM. The three detection families are intentionally bounded; they are not comprehensive. Correlation is a transparent actor/account/time-window heuristic, not causal attack-graph inference. SHA-256 hashes are integrity fingerprints, not digital signatures or trusted timestamps. Terraform was formatted and validated but not applied to an AWS account; real AWS behavior and costs have therefore not been tested. Simulations emit synthetic telemetry and make no cloud API calls. The visual web console, live cloud event collector, remediation automation and resource-graph attack-path inference are separate follow-on work.

## Next engineering extensions
- Expand detection coverage and map Security Hub control findings to first-class CloudShield findings.
- Add Checkov/tfsec policy scanning and review provider resources in an isolated, budget-controlled AWS account.
- Add opt-in AWS-backed simulations that collect actual CloudTrail records.
- Add resource-graph attack-path inference and analyst workflow state.
- Build the premium web console on top of the tested API/domain layer.

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]