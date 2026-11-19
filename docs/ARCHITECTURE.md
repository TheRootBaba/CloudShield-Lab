# Architecture

## Runtime

- cloudshield.api serves the Vite-built React command center from web/ and the local JSON API using Python standard-library HTTP components.
- cli.py exposes analysis, simulation, storage, evaluation, evidence signing and opt-in AWS inventory commands.
- App.jsx and styles.css implement the responsive React interface; Vite builds hashed JavaScript, CSS and font assets into web/.
- assets.py derives an observed-resource inventory and contextual relationship graph from stored event and finding evidence.
- attack_techniques.py attaches conservative, curated MITRE ATT&CK references to selected detection rules; mappings are coverage hypotheses, not confirmation of technique execution.
- evaluation.py calculates fixture-scoped confusion counts and per-rule detection metrics.
- evidence_signing.py creates and verifies detached Ed25519 signatures for valid Phase 10 bundles.
- aws_inventory.py provides an explicitly enabled, bounded, read-only inventory adapter; it does not claim complete AWS account discovery.
- pipeline.py normalizes events, applies explainable detection rules and groups findings into incidents.
- storage.py persists normalized events, findings and incidents transactionally in SQLite.
- graph.py creates a relationship graph with finding/event, actor, account and resource nodes. Observed resource references and temporal adjacency edges are labelled with their evidence.
- collector.py is an optional boto3 adapter for one-shot read-only CloudTrail LookupEvents requests.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /api/health | Service and collector capability status |
| GET | /api/dashboard | Stored evidence summary and recent records |
| GET | /api/analytics?window=24h | Bounded event/finding time-series aggregates and top rules |
| GET | /api/assets | Event-derived observed resource inventory |
| GET | /api/asset-graph | Resource relationship graph derived from observed evidence |
| GET | /api/incidents | Incident list |
| GET | /api/incidents/{id} | Incident, digest and relationship graph |
| GET | /api/findings | Stored findings |
| GET | /api/events | Normalized stored events and evidence fingerprints |
| GET | /api/evidence/{event_id} | Event and associated finding digests |
| GET | /api/rules | Rule inventory with curated ATT&CK references |
| GET | /api/incidents/{id}/workflow | Incident workflow state and activity history |
| GET | /api/incidents/{id}/export | Portable incident evidence bundle |
| GET | /api/collector/status | AWS SDK and local credential-source status |
| POST | /api/ingest | Analyze and persist supplied JSON |
| POST | /api/simulate | Generate and persist explicitly synthetic scenario telemetry |
| POST | /api/incidents/{id}/notes | Append an analyst note to local workflow history |
| POST | /api/evidence/verify | Verify a portable evidence bundle's hashes and references |
| PATCH | /api/incidents/{id}/workflow | Update validated workflow state, priority or assignee |
| POST | /api/collector/aws | Explicit one-shot CloudTrail lookup; requires opt-in environment flag |

The default API binds to loopback and preserves a single-user local mode. Optional multi-user mode adds browser authentication and workspace isolation. Non-loopback binds are refused unless multi-user mode and Secure cookies are enabled inside the supplied container profile. POST requests require JSON and same-origin Origin validation when an Origin header is supplied.

## Correlation and graph semantics

The incident builder groups findings by actor and account when adjacent finding timestamps are within a time window. The relationship graph includes event/finding nodes, actor and account context nodes, resource nodes derived from normalized resource identifiers, and temporal sequence hypotheses. Resource-reference edges reflect observed fields. Temporal sequence edges reflect membership in the same correlated incident and optional resource overlap. They do not establish causality, identity delegation, resource ownership or a complete attack path.

## Evidence

SQLite stores canonical JSON payloads and SHA-256 fingerprints. Hashes support integrity comparison but do not prove source authenticity, prevent database replacement or provide trusted timestamps. Legacy mode uses one local database; multi-user mode uses a distinct SQLite evidence database per workspace, selected only from the authenticated server-side session.

## AWS collector safety

The optional collector calls only CloudTrail LookupEvents. It is disabled unless CLOUDSHIELD_ENABLE_AWS_COLLECTOR=1 is set in the server process environment. Each request is operator-initiated, region-scoped, limited to a 1–1440 minute lookback and at most five pages. No polling, event subscription, resource creation or AWS write API is performed.

## Trust boundaries

- Imported JSON, synthetic fixtures and cloud responses are untrusted.
- The local server must not be exposed to untrusted networks.
- Terraform roots are independent examples; no API route runs Terraform.
- No AWS credentials are needed for offline tests and simulations.