# Phase 8 — Observed cloud asset inventory

## Implemented
- Derive a local inventory from resource identifiers observed in imported/synthetic events.
- Classify common AWS resource identifier types (IAM, S3, EC2/security groups/snapshots, RDS, Lambda, KMS).
- Track first/last observed timestamps, event counts, actors, accounts, regions and attached finding summaries.
- Expose read-only API endpoints for inventory and observed relationship graph.
- Graph links actors to accounts, actors to observed resources, and resources to accounts using contextual evidence labels.

## Data integrity and scope
The inventory is event-derived, not authoritative AWS enumeration. Assets absent from the evidence store are not represented. Actor-to-resource edges mean an event referenced a resource; they do not establish intent or causal attack paths. The feature requires no AWS calls and uses existing local SQLite evidence.
