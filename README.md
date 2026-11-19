# CloudShield Lab

**A local-first cloud security command center for detection, investigation and evidence-led verification.**

CloudShield is an engineering lab and portfolio project. It is not a production CSPM/SIEM, not a replacement for GuardDuty or Security Hub, and not a claim of comprehensive cloud threat detection.

## What is implemented

- Responsive security command center: overview, incidents, detections, relationship paths, evidence vault, data sources and rule library.
- Local HTTP API backed by the detection pipeline and SQLite evidence store.
- Optional browser authentication with scrypt password hashes, 12-hour revocable sessions, CSRF protection, role-based authorization, workspace invitations and separate SQLite evidence databases per workspace.
- CloudTrail and AWS Security Hub event normalization, plus Azure Activity Log normalization.
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
- Optional bounded read-only Azure Resource Manager inventory and subscription Activity Log collection; disabled unless explicitly enabled.

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

CloudTrail event arrays, CloudTrail Records documents, Security Hub Findings exports, Azure Activity Log exports, and EventBridge-style objects containing a detail object are supported. Use **Import events** in the UI. The request body is limited to 2 MiB. Evidence is stored in artifacts/evidence.sqlite3 by default. Set CLOUDSHIELD_DB to choose another path.

## Optional live AWS CloudTrail collection

Live collection is off by default and is a one-shot, read-only lookup. It uses the standard boto3 credential provider chain; CloudShield does not accept or store AWS secret keys.

1. Install the optional dependency: **python -m pip install -e ".[aws]"**.
2. Configure a local AWS profile or environment credentials with only cloudtrail:LookupEvents.
3. Explicitly enable the feature in the server process: **$env:CLOUDSHIELD_ENABLE_AWS_COLLECTOR="1"**
4. Start the app again and open **Data sources / AWS CloudTrail**. Choose a region and lookback up to 24 hours.

The collector reads up to five pages of 50 events (250 maximum per run), does not poll continuously, and makes no AWS write calls. AWS API usage and related services may incur charges under your account. Do not use root credentials. No AWS resources are created by the local API.

## Optional live Azure collection

Azure is supported as the second provider. Install **python -m pip install -e .[azure]**, authenticate using `az login` or another supported `DefaultAzureCredential` source, and set `AZURE_SUBSCRIPTION_ID`. Collection remains disabled until `CLOUDSHIELD_ENABLE_AZURE_COLLECTION=1` is set in the process environment. Then run `cloudshield azure-inventory --max-pages 10 --max-records 2000` or `cloudshield azure-activity-logs --lookback-hours 24 --max-pages 10 --max-records 2000`. The API exposes `GET /api/providers` and admin-only Azure collector routes. Minimum intended permissions are `Microsoft.Resources/subscriptions/resources/read` and `Microsoft.Insights/eventtypes/values/read`; see [docs/AZURE_PROVIDER.md](docs/AZURE_PROVIDER.md). The adapter covers one subscription and control-plane Activity Logs; it does not query Defender for Cloud, Entra ID sign-ins, data-plane logs or management groups. No live Azure calls are made by default.

## Detection and investigation boundaries

See docs/DETECTION_COVERAGE.md for rule IDs and supported patterns.

- Coverage is selected event-pattern detection, not comprehensive threat detection. Unsupported services, event shapes, data-plane activity and contextual signals can be missed.
- Synthetic scenarios generate fake CloudTrail-shaped JSON only. They do not execute attacks or call AWS.
- Incident grouping remains an actor/account/time-window heuristic. The relationship graph makes evidence-backed temporal and resource correlations visible, but does not infer verified causality or a complete attack path. Sequence hypotheses are bounded to 24 hours where timestamps are available; see docs/ATTACK_PATH_CORRELATION.md.
- The AWS collector is optional and reads CloudTrail management event history only. The Azure adapter reads subscription Activity Logs (control-plane) and ARM resource metadata. Neither is a streaming pipeline, full provider inventory, organization-wide deployment, or guaranteed complete audit feed.
- SHA-256 fingerprints detect content changes relative to a known digest; they are not digital signatures, trusted timestamps, or proof of source authenticity.
- Analyst workflow per incident: status transitions, priority, assignee, and append-only activity notes.
- Portable incident evidence bundles containing incident/event/finding digests, workflow history and a bundle manifest; verifier checks hash integrity and timeline references.
- Legacy loopback mode remains single-user. Optional multi-user mode partitions each workspace into a separate SQLite evidence database and derives tenant scope from the authenticated server-side session. Workflow actors are authenticated in multi-user mode; local-mode actor names remain user-supplied. Evidence bundle hashes are tamper-evident only relative to a trusted copy of the manifest. Phase 12 adds optional detached Ed25519 signatures when a trusted public key is supplied independently; signatures do not establish source truth or trusted time.

## Security and operational defaults

The server binds to 127.0.0.1 and rejects non-loopback bind addresses at startup. Uploaded JSON is treated as untrusted input; the API enforces a 2 MiB JSON-object body limit, content-type/length checks, cross-origin Origin rejection, request limits keyed to the TCP peer (forwarded headers are not trusted) and restrictive browser security headers. Mutating API operations are recorded in a local SQLite security audit table.

Legacy local mode supports optional API role tokens. For browser accounts and tenant isolation, set CLOUDSHIELD_AUTH_MODE=multi_user; the first account becomes the initial administrator and subsequent users join via single-use invitations. Passwords use scrypt hashes, sessions are HttpOnly/SameSite cookies with 12-hour expiry, and state-changing requests require CSRF validation. Administrators can invite analysts/responders, create separate workspaces and revoke member access. See docs/MULTI_USER_AUTH.md. The production Compose profile enables multi-user auth and Secure cookies by default and requires a unique `CLOUDSHIELD_BOOTSTRAP_TOKEN` (at least 32 characters) to protect first-admin registration. The setup key is passed only to the app container, not Caddy.

**Do not expose the Python listener directly to a LAN or public network.** The production profile places Caddy HTTPS ingress in front of the private API and requires multi-user auth. It is a single-host deployment template, not an HA SaaS platform. MFA/SSO, email verification, password recovery, external managed secrets/audit, monitoring, independent penetration testing and live cloud validation remain release gates. Do not enable shared server-side cloud credentials in multi-user mode; provider collectors are deliberately blocked until identities are tenant-scoped.

No cloud collection, resource creation, remediation or cloud writes happen unless an operator explicitly enables a read-only provider collector. Keep both provider toggles disabled for the offline $0 setup. Terraform examples remain separate and opt-in.

## Phases 9-10: incident workflow and evidence bundles

- Use the incident drawer to set workflow status (`new`, `acknowledged`, `in_progress`, `resolved`, `reopened`), priority, assignee and add analyst notes.
- Workflow changes and notes are retained in a local activity history.
- Export a portable JSON bundle from an incident and automatically verify it before download. The Evidence Vault can verify a previously exported bundle.
- API: `GET /api/incidents/{id}/workflow`, `PATCH /api/incidents/{id}/workflow`, `POST /api/incidents/{id}/notes`, `GET /api/incidents/{id}/export`, and `POST /api/evidence/verify`.
- Integrity checks validate incident/event/finding digests, manifest digest and event references. This is not cryptographic authenticity or trusted chain of custody.

See docs/PHASE_9_INCIDENT_RESPONSE.md and docs/PHASE_10_EVIDENCE_BUNDLES.md for implementation details and boundaries.

## Detection evaluation (Phase 11)

Run **cloudshield evaluate fixtures/detection_evaluation.json** to calculate per-rule and micro-averaged precision, recall, specificity and F1. The included 30-case labelled corpus currently passes 30/30 cases. These are deterministic fixture results only, not estimates of production false-positive or false-negative rates. See docs/PHASE_11_DETECTION_EVALUATION.md.

## Signed evidence bundles (Phase 12)

Install the optional signing dependency with **python -m pip install -e ".[signing]"**. Generate an encrypted Ed25519 key pair with **cloudshield keygen --private-key artifacts/cloudshield-signing-private.pem --public-key artifacts/cloudshield-signing-public.pem**. Then sign and verify a valid exported bundle using **cloudshield sign-bundle** and **cloudshield verify-signature**. The public key must be trusted independently; a signature does not prove the source telemetry is truthful or provide trusted timestamping. See docs/PHASE_12_SIGNED_EVIDENCE.md.

## Optional read-only AWS inventory (Phase 13)

Install boto3 with **python -m pip install -e ".[aws]"**, then explicitly set **$env:CLOUDSHIELD_ENABLE_AWS_INVENTORY="1"** before running **cloudshield aws-inventory --regions us-east-1 --max-pages 1 --output artifacts/aws-inventory.json**. The command is disabled by default, accepts only 1–5 explicit regions, and caps pagination. It lists selected resource metadata only; it is not complete organization-wide discovery. Tests use mocked clients and do not contact AWS. Review docs/PHASE_13_AWS_INVENTORY.md and approve the sandbox/cost boundary before a live run.

## Phase 14 offline hardening

Incident graph correlations now require explicit evidence, avoid ambiguous duplicate event IDs, cap valid timestamp gaps at 24 hours and mark sequence edges as non-causal. Optional multi-user browser auth and tenant-isolated workspaces are documented in docs/MULTI_USER_AUTH.md; enterprise identity and independent assurance remain external gates. See docs/ATTACK_PATH_CORRELATION.md and docs/SECURITY_THREAT_MODEL.md.

## Terraform safety

Examples remain under terraform/secure and terraform/vulnerable. Both default to no resource creation and require explicit opt-in. The vulnerable root intentionally creates insecure training fixtures. Never apply it to a production or shared account. Review cost, region, IAM permissions and teardown before any AWS apply.

## Tests

Run **python -m compileall -q src tests** and **python -m unittest discover -s tests -v**. For the React command center, run **npm ci** and **npm run build**. The CI authentication/recovery coverage gate is **python -m coverage run --source=cloudshield.auth,cloudshield.recovery -m unittest discover -s tests -v** followed by **python -m coverage report --fail-under=90**.

The suite covers normalization, selected detections, simulation, detection evaluation, signed evidence, mocked AWS inventory, incident grouping, graph semantics, API integration, SQLite persistence and Terraform safety fixtures.

MIT License.

## Offline completion and handoff

See docs/OFFLINE_COMPLETION.md for the offline verification snapshot. Phase 15–20 delivery and provider expansion are documented in docs/PHASES_15_20_REPORT.md and docs/PROVIDER_EXPANSION_REPORT.md. Browser authentication and tenant isolation are described in docs/MULTI_USER_AUTH.md; production ingress and workspace recovery are in docs/DEPLOYMENT_OPERATIONS.md and docs/FINALIZATION_RUNBOOK.md.

## Containerized local run

Docker Compose is provided for a local-only deployment. It runs as a non-root user, uses a read-only container filesystem with a persistent data volume, drops Linux capabilities, and publishes only `127.0.0.1:8765` on the host. Build and start with `docker compose up --build -d`, then open `http://127.0.0.1:8765`. Stop with `docker compose down`; preserve the named volume unless intentionally deleting local evidence. Do not change the local profile port binding to 0.0.0.0. The separate production profile is the only supported non-loopback template and requires HTTPS plus multi-user auth; see docs/DEPLOYMENT_OPERATIONS.md.

## SQLite backup and restore

Create a consistent online backup and SHA-256 manifest with `cloudshield backup --database artifacts/evidence.sqlite3 --output artifacts/backups/evidence-2026-11-19.sqlite3`. Verify it with `cloudshield verify-backup artifacts/backups/evidence-2026-11-19.sqlite3`; restore only to a new path with `cloudshield restore-backup artifacts/backups/evidence-2026-11-19.sqlite3 --destination artifacts/restore/evidence.sqlite3`. Verification checks the manifest digest and SQLite integrity. Store/sign the manifest independently for protection against an attacker who can modify both files.


## Multi-user browser sign-in and workspace isolation

For a local multi-user trial, set CLOUDSHIELD_AUTH_MODE=multi_user before starting the API. The first registered account becomes the administrator. Use the Team control to invite users or create a separate workspace. Each workspace has its own SQLite database; the server selects it from the signed-in session. See docs/MULTI_USER_AUTH.md for configuration, roles, invitation and security limitations.

## Production HTTPS deployment

compose.production.yaml runs the application on an internal-only Docker network behind Caddy; only Caddy is attached to the public edge network. Copy .env.production.example to .env.production, configure a real DNS name and TLS contact, generate a unique bootstrap key with `python -c "import secrets; print(secrets.token_urlsafe(48))"`, and store it in the private environment file. Validate/deploy with `docker compose --env-file .env.production -f compose.production.yaml config --quiet` and `docker compose --env-file .env.production -f compose.production.yaml up --build -d`. On Windows, `scripts/deploy-production.ps1` performs config/build/start plus internal and external HTTPS health checks. The app API port is not published. Do not deploy with the sample domain or without DNS, inbound 80/443, host firewall, secret-file ACLs, monitoring and independent security review. Production deployment and recovery procedures are in docs/DEPLOYMENT_OPERATIONS.md.

## Multi-workspace backup and recovery

Back up the authentication database and all tenant databases together with cloudshield backup-workspaces --auth-database artifacts/auth.sqlite3 --tenant-directory artifacts/tenants --output artifacts/backups/cloudshield-workspaces.zip. Verify with cloudshield verify-workspaces and restore to a new directory with cloudshield restore-workspaces. Quiesce writes for a consistent snapshot and store the archive plus manifest off-host. Windows Docker operators can use `scripts/backup-production.ps1` (stops the app briefly for a consistent auth+tenant snapshot and restarts it) and `scripts/recovery-drill.ps1` (verifies/restores to an isolated new directory). `scripts/deploy-production.ps1` performs a guarded deployment and HTTPS health check.
