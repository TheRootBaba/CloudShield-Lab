# Architecture

CloudShield's local pipeline is deliberately dependency-light:

1. JSON input is normalized into immutable `CloudEvent` records (CloudTrail and AWS Security Hub finding adapters).
2. Explainable detector rules create `Finding` records with rule IDs, severity, rationale and source evidence.
3. The analytics layer groups findings by actor and account, splitting clusters when adjacent findings exceed the configured time window.
4. Investigations retain the original event payload and a canonical SHA-256 evidence fingerprint.
5. The optional SQLite evidence store persists events, findings and incidents transactionally and idempotently.

## Trust boundaries

- Input fixtures, uploaded JSON and simulator output are untrusted input.
- The simulator creates synthetic JSON only; it never calls AWS APIs or performs network activity.
- Terraform is separate from the local pipeline. The secure and vulnerable roots are opt-in examples and no CLI command applies them.
- SQLite is a single-user local evidence store, not a multi-tenant production database.
- SHA-256 hashes identify canonical payloads; they do not prove source authenticity, prevent database replacement or provide trusted timestamps.

## Correlation semantics

The initial correlator groups findings by the same actor and account while adjacent findings remain within the configured time window. This is a transparent heuristic, not causal attribution or a complete attack-path graph. Timeline ordering uses parsed event timestamps with event IDs as deterministic tie-breakers. Missing or malformed timestamps remain grouped conservatively and should be investigated.

## Infrastructure

- `terraform/secure` provisions a CloudTrail evidence bucket with public access blocks, encryption and versioning, a multi-region trail, and Security Hub.
- `terraform/vulnerable` intentionally disables S3 public-access blocks and opens SSH to all IPv4 addresses for training/static validation only.
- Terraform formatting and provider-backed validation run in CI. No `apply` runs in CI.

## CLI

- `cloudshield analyze events.json`: normalize, detect, correlate and emit JSON.
- `cloudshield simulate all`: generate offline synthetic attack telemetry.
- `cloudshield investigate events.json EVENT_ID`: inspect a source event and findings.
- `cloudshield store events.json`: analyze and persist evidence to local SQLite.
- `cloudshield timeline`: query stored event evidence.
- `cloudshield incident INCIDENT_ID`: retrieve a persisted incident.

The SQLite database defaults to `artifacts/evidence.sqlite3`; use `--database` to select another path.
