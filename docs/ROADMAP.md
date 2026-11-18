# Delivery status — command center milestone

## Phase 1 — detection engine
- [x] Normalize CloudTrail records and Security Hub finding envelopes.
- [x] Preserve source payload, account, region, actor, resources and request/response context.
- [x] Add selected IAM, S3, EC2/network, CloudTrail, KMS, Lambda, RDS and root-login event-pattern rules.
- [x] Explain findings with rule IDs, severity, rationale and source evidence.
- [x] Maintain an explicit detection rule inventory and coverage limitations.

## Phase 2 — infrastructure
- [x] Separate secure and intentionally vulnerable Terraform roots.
- [x] Secure baseline includes encryption, versioning, public-access blocks, CloudTrail and Security Hub when explicitly enabled.
- [x] Vulnerable training root remains intentionally insecure and opt-in.
- [x] Both roots default to zero resource creation.
- [x] Terraform formatting and configuration validation are part of CI.

## Phase 3 — attack simulation
- [x] Offline synthetic IAM, public S3 and public SSH scenarios.
- [x] Add a multi-step synthetic sequence: privilege mutation, credential creation, CloudTrail disruption and exposed admin ingress.
- [x] Mark synthetic event provenance in normalized evidence.
- [x] Confirm zero cloud API calls from the simulator.

## Phase 4 — analytics and evidence
- [x] Correlate findings by actor/account and time window.
- [x] Produce deterministic incidents and chronological timelines.
- [x] Build explainable event, actor, account and resource relationship graphs.
- [x] Persist events, findings and incidents in SQLite with idempotent ingestion.
- [x] Preserve SHA-256 fingerprints and expose event-level evidence retrieval.

## Phase 5 — analyst command center
- [x] Responsive dark security operations UI.
- [x] Overview, incidents, detections, attack paths, evidence vault, data sources and rule library views.
- [x] Search/filter, incident drill-down, evidence inspection, JSON import and simulation controls.
- [x] Local HTTP API backed by the existing detection and evidence domain logic.
- [x] Empty-state behavior and no fabricated metrics.

## Phase 6 — optional live AWS ingestion
- [x] Opt-in one-shot read-only CloudTrail LookupEvents adapter.
- [x] Region and lookback limits, page limit, and no polling.
- [x] Collector disabled by default and uses the standard AWS credential chain.
- [ ] Validate against a real, isolated AWS account with least-privilege permissions and explicit cost approval.

## Verification completed locally
- 34 Python unit/integration tests pass.
- Python compilation succeeds.
- Browser JavaScript syntax check succeeds with Node.
- API integration tests cover empty startup, static assets, simulation, source provenance, graph and rule inventory.
- Terraform formatting and both root validations are checked locally.
- Local HTTP smoke test returned healthy API, empty dashboard, and static HTML/JS assets.
- A four-event synthetic sequence was ingested successfully into a separate smoke-test database.
- No AWS resources were created or modified. Live AWS collection was not run.

## Explicit remaining boundaries
This is still a local-first engineering lab, not a production CSPM/SIEM. Detection coverage is selected and not comprehensive. Simulations are synthetic and do not execute attacks. Incident grouping remains a heuristic; the relationship graph adds actor/account/resource context and temporal edges but is not a complete causal attack-path engine. The AWS collector is one-shot CloudTrail management-event history lookup, not streaming, organization-wide collection or guaranteed complete telemetry. There is no automated remediation, multi-user authentication, multi-tenant database, production deployment hardening or real AWS validation.

## Phase 9 — incident response workflow (implemented in feature branch)
- [x] Status transitions, priority, assignment and analyst notes per incident.
- [x] Persisted workflow state and activity history in SQLite.
- [x] Validate transitions and input lengths; unknown incidents return 404.
- [x] Workflow controls in incident investigation panel.
- [x] Workflow unit/API tests.

## Phase 10 — portable evidence bundle & integrity verifier (implemented in feature branch)
- [x] Export incident, referenced events, findings, workflow state/history and SHA-256 hashes as JSON.
- [x] Bundle manifest digest and counts.
- [x] Verify incident/event/finding digests, manifest and timeline-to-event references.
- [x] Export from incident view; verify bundle from Evidence Vault.
- [x] Tamper detection, malformed bundle and reference consistency tests.
- [ ] Digital signatures or external trusted timestamping (not implemented).

## Next engineering work
- Add service-specific fixtures, adversarial test cases, ATT&CK mapping and measured false-positive tuning.
- Validate the collector in an isolated AWS sandbox and document least-privilege IAM policy and cost boundaries.
- Add organization/account inventory and resource relationship ingestion.
- Add authentication and authorization before any shared or hosted deployment. Current workflow is local-only and analyst labels are user-entered, not authenticated.
- Consider graph algorithms only after trustworthy asset and identity relationship data is available.