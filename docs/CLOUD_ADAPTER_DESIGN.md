# Cloud provider adapter design

## Current state

Offline event normalization, mock-tested AWS CloudTrail collection and bounded mock-tested inventory exist. Live AWS validation, multi-region/organization coverage and authoritative inventory are deferred. This document defines the future adapter contract without making network calls or enabling AWS.

## Required adapter contract

Each provider adapter should expose `capabilities`, `required_permissions`, `collect_events(cursor, time_range, page_budget)`, and `inventory(scope, page_budget)`. Every response should include provider/account/tenant identity, region, collection start/end, cursor state, pages and API-call counts, truncation, partial failures, retry counts, permission errors and source provenance. A successful partial result must never be labelled complete.

## Pagination and resilience requirements

- Use provider continuation tokens exactly as returned; detect repeated tokens and stop safely.
- Bound pages, total records, elapsed time and concurrency per run.
- Retry only transient throttling/5xx/network failures with capped exponential backoff and jitter; do not retry authorization/validation errors.
- Respect provider retry hints and request quotas; expose retries and final failure in the report.
- Preserve successful pages when a later page fails, mark the result partial and include the failed operation/region.
- Avoid automatic polling, write APIs, remediation and resource creation in the read-only validation scope.
- Normalize provider timestamps to UTC while preserving original source timestamps and identifiers.
- Make least-privilege actions and resource scope explicit and test policy simulation separately from live calls.

## AWS deferred validation plan

After explicit user approval and an active isolated account: review the exact IAM policy, cost boundary, region allowlist, API-call/page budget and teardown/disable plan; use a dedicated non-root identity; validate CloudTrail LookupEvents and each inventory API independently; capture request counts, pagination, throttling and access-denied behavior; compare resource samples against the AWS console/API as ground truth; then revoke temporary permissions. No AWS action is authorized by this design document.
