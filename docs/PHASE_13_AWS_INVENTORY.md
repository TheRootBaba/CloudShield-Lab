# Phase 13 — bounded read-only AWS inventory

## Scope
The optional inventory adapter lists metadata for:
- EC2 instances and their state/type/VPC/subnet/IP/security-group references.
- EC2 security groups and inbound/outbound rule counts.
- S3 bucket names and creation timestamps (not bucket contents or bucket configuration).
- IAM role and IAM user names, ARNs and creation timestamps.

It does not enumerate every AWS service, inspect objects, evaluate effective IAM permissions, discover AWS Organizations accounts, or claim a complete cloud inventory.

## Explicit opt-in
Install the optional AWS SDK and enable the command only in a deliberate local shell:
```powershell
python -m pip install -e ".[aws]"
$env:CLOUDSHIELD_ENABLE_AWS_INVENTORY="1"
cloudshield aws-inventory --regions us-east-1 --max-pages 1 --output artifacts/aws-inventory.json
```
The environment variable is required for every invocation. It is not enabled by default. Supply 1–5 explicit region identifiers. Pagination is capped at 2 pages per operation. The report includes the API-call count and whether any response was truncated.

## Least-privilege IAM actions
The inventory requires only these list/describe actions:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "s3:ListAllMyBuckets",
      "iam:ListRoles",
      "iam:ListUsers"
    ],
    "Resource": "*"
  }]
}
```
The policy is read-only. Do not use root credentials. Use a dedicated sandbox role/profile and review the permissions against current AWS service documentation before attaching it.

## Safety and cost
No create, update, delete, apply, remediation or object-read API is called. The adapter does not store or accept AWS secret keys; it uses the standard boto3 credential chain. AWS account use has deliberately not been tested by the automated suite: tests use fake clients and make zero network requests. API requests are bounded, but confirm applicable AWS pricing, quotas and account policy before a live run. A successful untruncated result is still a partial inventory.
