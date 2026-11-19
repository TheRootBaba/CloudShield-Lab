# Cloud provider adapter design

## Supported providers

CloudShield now has two selectable provider adapters: AWS and Microsoft Azure. Both are disabled by default, read-only and explicitly invoked.

### AWS

- CloudTrail management event history through `LookupEvents`.
- Bounded EC2 instance/security-group, S3 bucket-name, IAM role/user metadata inventory.
- Standard botocore retry mode with four total attempts for live clients; continuation tokens are bounded and repeated tokens stop safely. Reported page/API counts are logical SDK operations and do not include internal retry attempts.
- Partial operation failures are reported without silently labelling the overall resource inventory complete.

### Azure

- Subscription-scoped ARM resource metadata inventory.
- Subscription Activity Log collection for a bounded UTC time window.
- `DefaultAzureCredential` authentication; Azure SDK retry policy configured for transient HTTP errors. Reported page/API counts are logical SDK operations and do not include internal retry attempts.
- Page and record caps, partial-page retention, continuation/truncation reporting, subscription provenance and required permission actions.
- Conservative detections for role assignment writes and diagnostic-setting deletion.

See `docs/AZURE_PROVIDER.md` for setup, scopes and limitations.

## Common adapter contract

Each provider result should expose provider/account/subscription identity, operation scope, collection start/end, page and record counts, API-call count, truncation, partial failures, retry behavior, permission errors and source provenance. A successful partial result must never be labelled complete.

## Pagination and resilience

- Use continuation tokens exactly as returned; detect repeated tokens and stop safely.
- Bound pages, total records, elapsed time and concurrency per run.
- Use provider SDK standard retry policies for transient throttling/5xx/network errors; do not retry authorization/validation failures.
- Preserve successful pages when a later page fails, mark the result partial and include the failed operation/scope.
- Respect provider retry hints and request quotas; expose final failures in the report.
- Normalize provider timestamps to UTC while preserving original source timestamps and identifiers.
- Make least-privilege actions and scope explicit; test permission boundaries with mocks before live validation.
- No write APIs, remediation, resource creation or deletion are part of these adapters.

## Live validation gate

A live test requires an active isolated account/subscription, reviewed read-only identity, exact scope and page/time budget, explicit cost boundary and approval for API calls. Capture throttling, access-denied and partial-page behavior, compare sample inventory with provider-native views, then revoke temporary access. No live AWS or Azure calls were made for this code extension. Read-only requests may still be subject to provider quotas or charges; no zero-cost claim is made for future live validation.
