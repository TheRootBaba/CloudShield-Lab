# Secure AWS telemetry baseline

Opt-in AWS configuration. It provisions an S3 evidence bucket, blocks all public access, enables AES-256 server-side encryption and versioning, creates a multi-region CloudTrail trail, and enables Security Hub.

**This can incur AWS charges** (CloudTrail management/data events, S3 storage/requests, Security Hub). The core demo never applies Terraform. Review the plan, set billing alerts, and destroy resources when finished.

```sh
terraform init
terraform validate
terraform plan
# Only after reviewing cost and permissions:
terraform apply
terraform destroy
```

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]