# CloudShield Lab

**Local-first cloud security detection, attack simulation and evidence-led investigation.**

CloudShield is an educational engineering lab. It normalizes CloudTrail-style events, detects selected risky changes, generates reproducible synthetic attack scenarios, correlates findings, and produces evidence-backed investigation reports.

## Implemented workflows
- CloudTrail and AWS Security Hub finding normalization with account, region, actor, resource identifiers and source format.
- Explainable detection for IAM policy mutations, public S3 bucket policies, and internet-exposed administrative ingress.
- Offline synthetic attack scenarios. The simulator makes zero cloud API calls.
- Incident grouping by actor/account and configurable time window, ordered timelines and stable incident identifiers.
- Event-level investigation with canonical SHA-256 evidence fingerprints.
- Idempotent local SQLite evidence storage for events, findings and incidents, with actor/account timeline filters.
- Separate Terraform secure and intentionally vulnerable AWS configurations. Both default to no resource creation.

## Honest limitations
This is not a production CSPM/SIEM or a replacement for GuardDuty/Security Hub. Synthetic events are not real AWS telemetry. Current incident grouping is a heuristic, not causal attack-graph correlation. Evidence hashes are integrity fingerprints, not signatures or trusted timestamps. A cloud event collector, frontend, automated remediation and resource-graph attack-path inference are not implemented. Detection coverage is intentionally limited. Terraform configurations are validated locally but have not been applied to AWS.

## Quick start (Python 3.10+, standard library only)
```powershell
pip install -e .
python -m unittest discover -s tests -v
cloudshield analyze fixtures/sample_cloudtrail.json
cloudshield simulate public-s3-policy --output artifacts/public-s3.json
cloudshield investigate fixtures/sample_cloudtrail.json demo-s3-001
cloudshield store artifacts/public-s3.json
cloudshield timeline
```

Without installation, prefix commands with `$env:PYTHONPATH="src"; python -m cloudshield.cli`.

## Terraform safety
Examples are under `terraform/secure` and `terraform/vulnerable`. Both require explicit opt-in via `-var enable_lab_resources=true`; default validation/planning creates no resources. The vulnerable configuration intentionally exposes SSH and disables S3 public-access protections. It is for isolated disposable accounts only and must never be applied to production/shared accounts.

Validate without deploying:
```powershell
terraform -chdir=terraform/secure init -backend=false
terraform -chdir=terraform/secure validate
terraform -chdir=terraform/vulnerable init -backend=false
terraform -chdir=terraform/vulnerable validate
```

Cloud resources can incur charges, including CloudTrail and Security Hub. Review permissions, region, budget alerts and teardown before any apply. No AWS credentials are needed for local Python tests or Terraform validation.

## Structure
- `src/cloudshield/`: normalization, detection, analytics, pipeline, simulator, SQLite evidence store and CLI.
- `fixtures/`: synthetic event data.
- `tests/`: unit and end-to-end tests.
- `terraform/secure` and `terraform/vulnerable`: opt-in Terraform configurations.
- `docs/`: architecture, roadmap and threat model.

MIT License.
