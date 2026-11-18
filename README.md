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
- **cloudshield timeline**

## Import formats

CloudTrail event arrays, CloudTrail Records documents, Security Hub Findings exports, and EventBridge-style objects containing a detail object are supported. Use **Import events** in the UI. The request body is limited to 2 MiB. Evidence is stored in artifacts/evidence.sqlite3 by default. Set CLOUDSHIELD_DB to choose another path.

## Optional live AWS CloudTrail collection

Live collection is off by default and is a one-shot, read-only lookup. It uses the standard boto3 credential provider chain; CloudShield does not accept or store AWS secret keys.

1. Install the optional dependency: **python -m pip install -e ".[aws]"**.
2. Configure a local AWS profile or environment credentials with only cloudtrail:LookupEvents.
3. Explicitly enable the feature in the server process: **$env:CLOUDSHIELD_ENABLE_AWS_COLLECTOR="1"**
4. Start the app again and open **Data sources → AWS CloudTrail**. Choose a region and lookback up to 24 hours.

The collector reads up to five pages of 50 events (250 maximum per run), does not poll continuously, and makes no AWS write calls. AWS API usage and related services may incur charges under your account. Do not use root credentials. No AWS resources are created by the local API.

## Detection and investigation boundaries

See docs/DETECTION_COVERAGE.md for rule IDs and supported patterns.

- Coverage is selected event-pattern detection, not comprehensive threat detection. Unsupported services, event shapes, data-plane activity and contextual signals can be missed.
- Synthetic scenarios generate fake CloudTrail-shaped JSON only. They do not execute attacks or call AWS.
- Incident grouping remains an actor/account/time-window heuristic. The relationship graph makes temporal and resource overlap visible, but does not infer verified causality or a complete attack path.
- The AWS collector is optional and reads CloudTrail management event history only. It is not a streaming pipeline, organization-wide deployment, or guaranteed complete audit feed.
- SHA-256 fingerprints detect content changes relative to a known digest; they are not digital signatures, trusted timestamps, or proof of source authenticity.
- Analyst workflow per incident: status transitions, priority, assignee, and append-only activity notes.
- Portable incident evidence bundles containing incident/event/finding digests, workflow history and a bundle manifest; verifier checks hash integrity and timeline references.
- The SQLite store is single-user and local, not a multi-tenant production database. Workflow actor names are user-supplied and are not authenticated. Evidence bundle hashes are tamper-evident only relative to a trusted copy of the manifest; bundles are not digitally signed.

## Security and operational defaults

The server binds to 127.0.0.1. Do not expose it to a public network. No authentication is implemented because this is a loopback-only local lab. Do not bind to 0.0.0.0 or put it behind a public reverse proxy without authentication, authorization, CSRF protection and deployment hardening.

Uploaded JSON is treated as untrusted input. The local API enforces a 2 MiB body limit and sends restrictive browser security headers. No cloud collection, resource creation, remediation or AWS writes happen unless the operator explicitly enables the one-shot collector. Terraform examples remain separate and opt-in.

## Incident workflow and evidence bundles

- Use the incident drawer to set workflow status (`new`, `acknowledged`, `in_progress`, `resolved`, `reopened`), priority, assignee and add analyst notes.
- Workflow changes and notes are retained in a local activity history.
- Export a portable JSON bundle from an incident and automatically verify it before download. The Evidence Vault can verify a previously exported bundle.
- API: `GET /api/incidents/{id}/workflow`, `PATCH /api/incidents/{id}/workflow`, `POST /api/incidents/{id}/notes`, `GET /api/incidents/{id}/export`, and `POST /api/evidence/verify`.
- Integrity checks validate incident/event/finding digests, manifest digest and event references. This is not cryptographic authenticity or trusted chain of custody.

## Terraform safety

Examples remain under terraform/secure and terraform/vulnerable. Both default to no resource creation and require explicit opt-in. The vulnerable root intentionally creates insecure training fixtures. Never apply it to a production or shared account. Review cost, region, IAM permissions and teardown before any AWS apply.

## Tests

Run **python -m compileall -q src tests** and **python -m unittest discover -s tests -v**.

The suite covers normalization, selected detections, simulation, incident grouping, graph semantics, API integration, SQLite persistence and Terraform safety fixtures.

MIT License.