# Architecture

## Runtime

- cloudshield.api serves the static command center and local JSON API using Python standard-library HTTP components.
- pipeline.py normalizes events, applies explainable detection rules and groups findings into incidents.
- storage.py persists normalized events, findings and incidents transactionally in SQLite.
- graph.py creates a relationship graph with finding/event, actor, account and resource nodes. Observed resource references and temporal adjacency edges are labelled with their evidence.
- collector.py is an optional boto3 adapter for one-shot read-only CloudTrail LookupEvents requests.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /api/health | Service and collector capability status |
| GET | /api/dashboard | Stored evidence summary and recent records |
| GET | /api/incidents | Incident list |
| GET | /api/incidents/{id} | Incident, digest and relationship graph |
| GET | /api/findings | Stored findings |
| GET | /api/events | Normalized stored events and evidence fingerprints |
| GET | /api/evidence/{event_id} | Event and associated finding digests |
| GET | /api/rules | Rule inventory |
| GET | /api/collector/status | AWS SDK and local credential-source status |
| POST | /api/ingest | Analyze and persist supplied JSON |
| POST | /api/simulate | Generate and persist explicitly synthetic scenario telemetry |
| POST | /api/collector/aws | Explicit one-shot CloudTrail lookup; requires opt-in environment flag |

The API binds to loopback by default and has no user authentication. It is intended for a single-user local lab only. POST requests require JSON and same-origin requests when an Origin header is supplied.

## Correlation and graph semantics

The incident builder groups findings by actor and account when adjacent finding timestamps are within a time window. The relationship graph includes event/finding nodes, actor and account context nodes, resource nodes derived from normalized resource identifiers, and temporal sequence hypotheses. Resource-reference edges reflect observed fields. Temporal sequence edges reflect membership in the same correlated incident and optional resource overlap. They do not establish causality, identity delegation, resource ownership or a complete attack path.

## Evidence

SQLite stores canonical JSON payloads and SHA-256 fingerprints. Hashes support integrity comparison but do not prove source authenticity, prevent database replacement or provide trusted timestamps. The database is single-user local storage.

## AWS collector safety

The optional collector calls only CloudTrail LookupEvents. It is disabled unless CLOUDSHIELD_ENABLE_AWS_COLLECTOR=1 is set in the server process environment. Each request is operator-initiated, region-scoped, limited to a 1–1440 minute lookback and at most five pages. No polling, event subscription, resource creation or AWS write API is performed.

## Trust boundaries

- Imported JSON, synthetic fixtures and cloud responses are untrusted.
- The local server must not be exposed to untrusted networks.
- Terraform roots are independent examples; no API route runs Terraform.
- No AWS credentials are needed for offline tests and simulations.