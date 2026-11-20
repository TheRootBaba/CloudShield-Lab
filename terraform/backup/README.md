# Offsite workspace backup target

This is an opt-in AWS backup target, separate from the CloudTrail collector role.

- S3 Block Public Access, versioning, TLS-only bucket policy and SSE-KMS.
- S3 Object Lock in COMPLIANCE mode with a configurable 30–3650 day default retention.
- A dedicated uploader role trusted by one deployment principal and a unique STS ExternalId.
- The uploader can write and verify objects under `cloudshield/`; it cannot delete objects or change bucket policy/retention.
- All resources default to zero creation. Review cost, retention, legal hold and account ownership before apply.

Example (generate the external ID with a secure password manager or `python -c "import secrets; print(secrets.token_urlsafe(36))"`):

```sh
terraform init
terraform validate
terraform plan -var='enable_backup_resources=true' \
  -var='backup_uploader_principal_arn=arn:aws:iam::123456789012:role/cloudshield-deployment' \
  -var='backup_external_id=REPLACE_WITH_RANDOM_VALUE'
# Only after security/cost/legal review:
terraform apply
```

Object Lock COMPLIANCE retention cannot be shortened by an administrator. This is intentionally strict and may conflict with deletion/legal obligations; choose retention only after policy review. The app's archive manifest is integrity evidence, not an independent signature. Store its SHA-256 and signing keys outside this bucket as well.
