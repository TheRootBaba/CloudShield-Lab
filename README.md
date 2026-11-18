# CloudShield-Lab

CloudShield Lab is a cloud security verification platform for detecting risky
infrastructure changes, investigating attack paths, automating guarded
remediation, and continuously validating security fixes. It combines a Python
analysis package with Terraform and AWS security telemetry.

## Python package

Install the package locally and run its tests:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

Analyze a Terraform plan JSON file:

```bash
terraform show -json tfplan > plan.json
cloudshield plan.json
```

The package provides:

- Terraform plan parsing and detection of public ingress, public S3 buckets,
  and disabled CloudTrail logging.
- CloudTrail and AWS Security Hub event normalization.
- Cycle-safe attack graph and attack-path discovery.
- Remediation proposals that require explicit approval and an allowed action.
- Validation callbacks for confirming that a finding has been resolved.

## AWS example

The `terraform/` directory creates an encrypted CloudTrail trail, a restricted
trail evidence bucket, and enables AWS Security Hub in the selected region.

```bash
cd terraform
terraform init
terraform plan
terraform apply
```
