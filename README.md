# CloudShield Lab

**A local-first cloud security command center for detection, investigation and evidence-led verification.**

CloudShield is an engineering lab and portfolio project. It is not a production CSPM/SIEM, not a replacement for GuardDuty or Security Hub, and not a claim of comprehensive cloud threat detection.

## What is implemented

- Responsive security command center: overview, incidents, detections, relationship paths, evidence vault, data sources and rule library.
- Local HTTP API backed by the detection pipeline and SQLite evidence store.
- CloudTrail and AWS Security Hub event normalization.
- Explainable detections for selected IAM, S3, EC2/network, CloudTrail, KMS, Lambda and RDS event patterns.
- Offline synthetic scenarios, including a four-step multi-stage sequence. Synthetic source provenance is retained.
- Incident grouping by actor/account and time window, with a graph view of observed time/resource relationships. Graph edges are hypotheses, not proof of causation.
- SHA-256 evidence fingerprints for canonical stored event and incident payloads.
- Optional, explicit, read-only AWS CloudTrail LookupEvents collection. Disabled by default.
- Detection validation suite with curated MITRE ATT&CK technique references, positive/negative/adversarial cases and mapping-integrity checks; real-world detection accuracy is not measured.
- Event-derived AWS asset inventory and relationship graph, including observed actors, accounts, regions, timestamps, event counts and finding associations; this is not authoritative cloud-resource enumeration.
- White-first responsive React command center with analytics, detection library, observed assets and relationship views.
- A labelled detection evaluation harness with per-rule metrics; fixture metrics are not production accuracy claims.
- Optional Ed25519 signatures for portable incident evidence bundles, using encrypted private keys and detached signatures.
- Optional bounded read-only AWS inventory for selected EC2, security-group, S3 bucket-name and IAM metadata; disabled unless explicitly enabled.

## Quick start (Windows PowerShell)

1. Open PowerShell in the repository directory.
2. Install the project: **python -m pip install -e .**
3. Run tests: **python -m unittest discover -s tests -v**
4. Start the app: **python -m cloudshield.api**
5. Open **http://127.0.0.1:8765**.

The first run is intentionally empty. Select **Run simulation** to create clearly marked synthetic lab data, or import your own CloudTrail / Security Hub JSON.

CLI examples:
- **cloudshield analyze fixtures/sample_cloudtrail.json**
- **cloudshield simulate multi-stage-compromise --output artifacts/multi-stage.json**
- **cloudshield store artifacts/multi-stage.json**
- **cloudshield evaluate fixtures/detection_evaluation.json**
- **cloudshield timeline**

## Import formats

CloudTrail event arrays, CloudTrail Records documents, Security Hub Findings exports, and EventBridge-style objects containing a detail object are supported. Use **Import events** in the UI. The request body is limited to 2 MiB. Evidence is stored in artifacts/evidence.sqlite3 by default. Set CLOUDSHIELD_DB to choose another path.

## Optional live AWS CloudTrail collection

Live collection is off by default and is a one-shot, read-only lookup. It uses the standard boto3 credential provider chain; CloudShield does not accept or store AWS secret keys.

1. Install the optional dependency: **python -m pip install -e ".[aws]"**.
2. Configure a local AWS profile or environment credentials with only cloudtrail:LookupEvents.
3. Explicitly enable the feature in the server process: **$env:CLOUDSHIELD_ENABLE_AWS_COLLECTOR="1"**
4. Start the app again and open **Data sources â†’ AWS CloudTrail**. Choose a region and lookback up to 24 hours.

The collector reads up to five pages of 50 events (250 maximum per run), does not poll continuously, and makes no AWS write calls. AWS API usage and related services may incur charges under your account. Do not use root credentials. No AWS resources are created by the local API.

## Detection and investigation boundaries

See docs/DETECTION_COVERAGE.md for rule IDs and supported patterns.

- Coverage is selected event-pattern detection, not comprehensive threat detection. Unsupported services, event shapes, data-plane activity and contextual signals can be missed.
- Synthetic scenarios generate fake CloudTrail-shaped JSON only. They do not execute attacks or call AWS.
- Incident grouping remains an actor/account/time-window heuristic. The relationship graph makes evidence-backed temporal and resource correlations visible, but does not infer verified causality or a complete attack path. Sequence hypotheses are bounded to 24 hours where timestamps are available; see docs/ATTACK_PATH_CORRELATION.md.
- The AWS collector is optional and reads CloudTrail management event history only. It is not a streaming pipeline, organization-wide deployment, or guaranteed complete audit feed.
- SHA-256 fingerprints detect content changes relative to a known digest; they are not digital signatures, trusted timestamps, or proof of source authenticity.
- Analyst workflow per incident: status transitions, priority, assignee, and append-only activity notes.
- Portable incident evidence bundles containing incident/event/finding digests, workflow history and a bundle manifest; verifier checks hash integrity and timeline references.
- The SQLite store is single-user and local, not a multi-tenant production database. Workflow actor names are user-supplied and are not authenticated. Evidence bundle hashes are tamper-evident only relative to a trusted copy of the manifest. Phase 12 adds optional detached Ed25519 signatures when a trusted public key is supplied independently; signatures do not establish source truth or trusted time.

## Security and operational defaults

The server binds to 127.0.0.1 and rejects non-loopback bind addresses at startup. Uploaded JSON is treated as untrusted input; the API enforces a 2 MiB JSON-object body limit, content-type/length checks, cross-origin Origin rejection, per-IP request limits and restrictive browser security headers. Mutating API operations are recorded in a local SQLite security audit table.

Optional API role tokens can be configured with unique `CLOUDSHIELD_ADMIN_TOKEN`, `CLOUDSHIELD_RESPONDER_TOKEN`, and `CLOUDSHIELD_ANALYST_TOKEN` values (each at least 32 characters). When any role token is configured, API requests other than `/api/health` require `Authorization: Bearer <token>`. Analysts can read and verify bundles; responders can change workflow, add notes, ingest and simulate; only admins can invoke the opt-in AWS collector. Tokens are long-lived environment secrets and must not be committed. When no tokens are configured, the app remains unauthenticated in loopback-only local mode.

**Do not expose the Python listener directly to a LAN or public network.** The React UI does not yet implement a login/token lifecycle, and this project is not multi-tenant. Remote access requires a separately hardened HTTPS/VPN reverse proxy and server-side identity/token injection, plus the external controls listed in `docs/SECURITY_THREAT_MODEL.md` and `docs/RELEASE_ASSURANCE.md`. API tokens alone do not make a hosted deployment production-ready.

No cloud collection, resource creation, remediation or AWS writes happen unless an operator explicitly enables the optional collector. Keep AWS collector/inventory disabled for the $0 offline setup. Terraform examples remain separate and opt-in.

## Phases 9-10: incident workflow and evidence bundles

- Use the incident drawer to set workflow status (`new`, `acknowledged`, `in_progress`, `resolved`, `reopened`), priority, assignee and add analyst notes.
- Workflow changes and notes are retained in a local activity history.
- Export a portable JSON bundle from an incident and automatically verify it before download. The Evidence Vault can verify a previously exported bundle.
- API: `GET /api/incidents/{id}/workflow`, `PATCH /api/incidents/{id}/workflow`, `POST /api/incidents/{id}/notes`, `GET /api/incidents/{id}/export`, and `POST /api/evidence/verify`.
- Integrity checks validate incident/event/finding digests, manifest digest and event references. This is not cryptographic authenticity or trusted chain of custody.

See docs/PHASE_9_INCIDENT_RESPONSE.md and docs/PHASE_10_EVIDENCE_BUNDLES.md for implementation details and boundaries.

## Detection evaluation (Phase 11)

Run **cloudshield evaluate fixtures/detection_evaluation.json** to calculate per-rule and micro-averaged precision, recall, specificity and F1. The included 26-case labelled corpus currently passes 26/26 cases. These are deterministic fixture results only, not estimates of production false-positive or false-negative rates. See docs/PHASE_11_DETECTION_EVALUATION.md.

## Signed evidence bundles (Phase 12)

Install the optional signing dependency with **python -m pip install -e ".[signing]"**. Generate an encrypted Ed25519 key pair with **cloudshield keygen --private-key artifacts/cloudshield-signing-private.pem --public-key artifacts/cloudshield-signing-public.pem**. Then sign and verify a valid exported bundle using **cloudshield sign-bundle** and **cloudshield verify-signature**. The public key must be trusted independently; a signature does not prove the source telemetry is truthful or provide trusted timestamping. See docs/PHASE_12_SIGNED_EVIDENCE.md.

## Optional read-only AWS inventory (Phase 13)

Install boto3 with **python -m pip install -e ".[aws]"**, then explicitly set **$env:CLOUDSHIELD_ENABLE_AWS_INVENTORY="1"** before running **cloudshield aws-inventory --regions us-east-1 --max-pages 1 --output artifacts/aws-inventory.json**. The command is disabled by default, accepts only 1â€“5 explicit regions, and caps pagination. It lists selected resource metadata only; it is not complete organization-wide discovery. Tests use mocked clients and do not contact AWS. Review docs/PHASE_13_AWS_INVENTORY.md and approve the sandbox/cost boundary before a live run.

## Phase 14 offline hardening

Incident graph correlations now require explicit evidence, avoid ambiguous duplicate event IDs, cap valid timestamp gaps at 24 hours and mark sequence edges as non-causal. API startup rejects non-loopback bind addresses while authentication and tenant isolation remain unimplemented. See docs/ATTACK_PATH_CORRELATION.md.

## Terraform safety

Examples remain under terraform/secure and terraform/vulnerable. Both default to no resource creation and require explicit opt-in. The vulnerable root intentionally creates insecure training fixtures. Never apply it to a production or shared account. Review cost, region, IAM permissions and teardown before any AWS apply.

## Tests

Run **python -m compileall -q src tests** and **python -m unittest discover -s tests -v**. For the React command center, run **npm ci** and **npm run build**.

The suite covers normalization, selected detections, simulation, detection evaluation, signed evidence, mocked AWS inventory, incident grouping, graph semantics, API integration, SQLite persistence and Terraform safety fixtures.

MIT License.

## Offline completion and handoff

See docs/OFFLINE_COMPLETION.md for the 19 November 2026 offline verification snapshot and zero-dollar AWS boundary. The Phase 15?20 offline tranche is documented in `docs/PHASES_15_20_REPORT.md`, with threat model, evidence custody, detection methodology, provider adapter design, deployment operations and release assurance in the adjacent docs.
