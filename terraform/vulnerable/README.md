# Intentionally vulnerable Terraform fixtures

**Do not apply this configuration to a real or shared AWS account.** It intentionally disables S3 public-access blocks and exposes SSH to all IPv4 addresses. The preferred workflow is static validation only:

```sh
terraform init -backend=false
terraform validate
terraform plan
```

If you choose to apply in a disposable isolated account, understand the risk and cost first, use no sensitive data, restrict the lab's lifetime, and destroy immediately. No CloudShield command applies this configuration.

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]