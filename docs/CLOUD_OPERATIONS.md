# Cloud connections, collection and operations

This document describes the tenant-scoped cloud integration and operational controls added in the Phase 21 implementation.

## Security model

- Each workspace has a separate SQLite evidence database and a separate provider connection record.
- A global uniqueness registry prevents the same AWS role ARN or the same Azure tenant/subscription/client-identity tuple from being assigned to multiple CloudShield workspaces.
- Cloud credentials are not entered into the UI or stored in CloudShield. AWS uses a workspace-specific STS ExternalId; Azure uses an explicitly selected managed identity or workload identity federation.
- Connections start disabled. An administrator must configure the identity, successfully test it, then explicitly enable scheduled collection.
- All collector endpoints are administrator-only. Collection is read-only, bounded and uses SDK retry policies.
- The collector worker is a separate Compose service. It reads each workspace's own provider config and evidence database; it does not use a shared customer credential.
- The default polling interval is 300 seconds; allowed range is 60–3600 seconds. Event ingestion is idempotent. AWS lookback includes an overlap; Azure uses a bounded lookback. Inventory refresh runs every six hours and is deliberately incomplete.
- No production provider write adapter is installed. The guarded response execution route returns HTTP 503 until a reviewed adapter is available; dry-run and approval records do not mutate cloud resources.

## AWS setup

1. In CloudShield **Data sources**, enter the AWS read-only IAM role ARN and default region.
2. Save the role. CloudShield generates a workspace ExternalId and displays it once.
3. In the target AWS account, configure the role trust policy. Replace the principal with the deployment role used by the CloudShield worker, and replace the ExternalId with the one displayed by the workspace.

Example trust relationship:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111122223333:role/cloudshield-runtime"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "REPLACE_WITH_WORKSPACE_EXTERNAL_ID"}}
  }]
}
```

Attach a customer-managed read-only policy scoped to the actions CloudShield calls:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "cloudtrail:LookupEvents",
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

4. Return to CloudShield and choose **Test identity**. This verifies STS account identity and CloudTrail read permission. Only after a successful test can collection be enabled.
5. Use **Collect CloudTrail now** or **Refresh inventory** for a one-shot administrator-triggered check. The worker then polls enabled workspaces on its schedule.

The deployment identity itself needs only `sts:AssumeRole` on the customer roles. Use a task role / instance profile / workload identity; do not put long-lived AWS access keys in the application environment.

## Azure setup

1. Create a dedicated user-assigned managed identity in the target tenant, or configure workload identity federation for the CloudShield worker.
2. Assign a custom role at the target subscription scope with only:
   - `Microsoft.Insights/eventtypes/values/read`
   - `Microsoft.Resources/subscriptions/resources/read`
3. In CloudShield **Data sources**, enter the tenant ID, subscription ID and the identity's client ID.
4. Choose **Test identity**. This checks resource-list and Activity Log read access. Enable collection only after the test succeeds.

For workload identity federation, the runtime must provide `AZURE_FEDERATED_TOKEN_FILE` and a valid workload token file; the workspace-specific client ID is taken from its connection record. For managed identity, the worker uses `ManagedIdentityCredential(client_id=...)`. The code intentionally does not fall back to a shared Azure CLI/developer credential chain or client secret.

## Collection limits and status

- AWS CloudTrail: up to five pages per polling cycle; lookback is based on the configured polling interval with a five-minute overlap and a 24-hour cap.
- Azure Activity Logs: up to five pages and 1,000 records per scheduled cycle; bounded lookback, maximum 24 hours.
- Inventory: AWS one configured region and one page per six-hour scheduled refresh; Azure up to five pages / 1,000 records. These are observed metadata snapshots, not authoritative full-cloud inventory.
- SDK standard retry/backoff is enabled. Repeated continuation tokens and partial failures are surfaced by the provider adapters.
- **Data sources** shows provider test/collection timestamps, last error, enabled state, worker heartbeat and stored live inventory.
- `GET /api/health/ready` reports database readiness and whether the collector worker heartbeat is current. It is suitable for an external uptime check, not a replacement for centralized metrics or paging.

## Alerts and email

- New HIGH and CRITICAL findings create deduplicated workspace alerts.
- Alerts appear in **Alerts & response** and can be acknowledged by responders/admins.
- The worker can email active workspace admins and responders through authenticated SMTP with STARTTLS. It sends only severity, title and an alert reference—not raw telemetry or credentials.
- Email is optional. Without SMTP configuration, in-app alerts continue to work.

To enable SMTP, create a host-side file containing only the SMTP password and protect it with OS permissions. Copy the example overlay to an operationally managed compose file and set the required environment variables:

```powershell
$env:CLOUDSHIELD_SMTP_PASSWORD_HOST_FILE = "C:\\secure\\cloudshield-smtp-password.txt"
$env:CLOUDSHIELD_SMTP_HOST = "smtp.example.com"
$env:CLOUDSHIELD_SMTP_USERNAME = "cloudshield-alerts"
$env:CLOUDSHIELD_SMTP_FROM = "cloudshield@example.com"
$env:CLOUDSHIELD_PUBLIC_URL = "https://cloudshield.example.com"
docker compose --env-file .env.production -f compose.production.yaml -f compose.production.smtp.example.yaml up -d
```

The overlay mounts the password as a Docker secret in the worker. Do not commit the password file or SMTP credentials. Delivery retries are bounded to five attempts with backoff.

## Controlled response workflow (Phase 23 foundation)

- A responder requests one action from the finding-specific catalogue; policy/trust findings and Azure findings without an action-specific plan do not receive unrelated remediation suggestions.
- A workspace administrator makes the initial independent approve/reject decision. Requester self-approval is blocked.
- `POST /api/responses/{request_id}/dry-run` builds a deterministic, expiring action plan. It reports exact resource IDs, inventory matches, unresolved targets, required permission, missing action parameters and blast radius. Dry-run never calls a provider.
- Sensitive actions require two additional distinct administrator approvals tied to the exact plan digest. Neither the requester nor initial approver can supply these approvals.
- `POST /api/responses/{request_id}/execution-approval` records an execution approval. `POST /api/responses/{request_id}/execute` requires an idempotency key, matching unexpired plan digest, resolved inventory targets, quorum, deployment opt-in and a service-wide kill switch that has been explicitly disabled.
- The kill switch is stored in the shared auth database and is enabled by default. Any workspace administrator may set `enabled=true` through `POST /api/responses/control/kill-switch` to stop execution immediately. A tenant administrator cannot disable the service-wide switch. Only a local deployment operator can disable it with `cloudshield response-kill-switch --auth-database artifacts/auth.sqlite3 --disable --confirm-disable "DISABLE CLOUDSHIELD RESPONSE EXECUTION"`; re-enable it with the same command and `--enable`. The CLI writes a local security-audit record.
- A failed or attempted request cannot be re-executed under a new idempotency key; it requires a new reviewed request. Execution history records result, failure code and adapter-supplied rollback metadata.
- **No production AWS/Azure write adapter is registered in this build.** Execution therefore fails closed even if all approvals are present. The adapter contract is tested with a sandbox fake, but actual provider actions, automatic rollback and provider-specific permission policies require isolated cloud acceptance and independent review before adapters can be installed.

## MFA and SSO

CloudShield's Firebase login flow supports:
- Firebase TOTP second-factor challenges using `TotpMultiFactorGenerator`.
- One configured Firebase OIDC or SAML provider through `CLOUDSHIELD_FIREBASE_SSO_PROVIDER_ID` (for example `oidc.company` or `saml.company`).

To activate these features:
1. Enable Firebase Authentication with Identity Platform and add TOTP as a second factor.
2. Have each user open **Account security**, enroll a TOTP authenticator using the displayed manual setup key / otpauth URI, and preferably enroll a second device before enforcement.
3. Only after enrollment is complete, set the Firebase TOTP policy to the required enforcement level.
4. Register the OIDC/SAML provider in Firebase, set `CLOUDSHIELD_FIREBASE_SSO_PROVIDER_ID` in the private deployment environment (for example `oidc.company` or `saml.company`), and add the deployed hostname to Firebase authorized domains.

The application cannot enable Firebase console features or verify identity-provider metadata from source code. SMS MFA and recovery codes are not implemented by this client flow; keep an administrator-assisted recovery process and do not enforce MFA until users have enrolled working factors.

## Offsite backup and restore drill

The new `terraform/backup` root is opt-in and provisions:
- A private, versioned S3 bucket with SSE-KMS and key rotation.
- S3 Object Lock COMPLIANCE default retention.
- A dedicated uploader role restricted to `cloudshield/`, trusted by one deployment principal plus a unique ExternalId.
- No delete permission for the uploader.

All resources default to zero creation. COMPLIANCE retention cannot be shortened; choose the retention period only after legal and data-retention review.

1. Apply the backup Terraform root only after review and obtain the bucket, KMS key and uploader role outputs.
2. Configure an AWS CLI profile to assume the uploader role with its ExternalId.
3. Create a consistent workspace archive with `scripts/backup-production.ps1` (it stops both app and worker writers and restarts both services in a finally block).
4. Upload and verify archive and sidecar manifest with `scripts/offsite-backup.ps1`.
5. Run `scripts/offsite-restore-drill.ps1` into a new isolated directory. It downloads, verifies and restores without touching the live data volume.

No backup bucket has been applied and no offsite restore drill has been executed for this project yet.

## Production monitoring boundary

The app exposes liveness at `/api/health`, database/worker readiness at `/api/health/ready`, and administrator-only low-cardinality counters at `/api/metrics`. Collector replicas use shared-database per-workspace leases, owner-checked renewal around bounded provider operations, owner-checked release, expiry/reclaim, per-worker heartbeats and service-wide counters. The lease implementation is SQLite-backed and requires replicas to share a reliable database volume; it is not safe to place SQLite on an arbitrary network filesystem or use it as a multi-region coordination system. Move leases and durable jobs to PostgreSQL/a dedicated queue before multi-host scaling. Docker health checks restart unhealthy containers. These signals do not provide centralized log retention, SLO dashboards, pager routing, multi-region failover or on-call coverage. Configure an external monitor for health endpoints, worker lease contention, stale heartbeats, failed backups and SMTP delivery backlog.
