# Threat model

## Purpose and deployment boundary

CloudShield Lab is a defensive engineering lab. The default runtime binds to 127.0.0.1 and is intended for one local analyst. It has no user authentication or multi-tenant isolation. Do not expose it to a LAN, public network, reverse proxy or hosted environment without adding authentication, authorization, CSRF protections, rate limits, audit controls and deployment hardening.

## Assets

- Integrity of detection rules, source code and test fixtures.
- Confidentiality of imported CloudTrail / Security Hub records and local SQLite evidence.
- Integrity of evidence fingerprints and incident timelines.
- AWS credentials available through the local credential provider chain.
- Cloud account availability and cost boundaries.

## Threats considered

- Malformed or oversized JSON import payloads.
- Cross-origin browser requests targeting the loopback API.
- Untrusted event fields attempting to inject HTML into the analyst interface.
- Local database replacement or tampering.
- Unauthorized use of the local AWS credential chain.
- Unexpected CloudTrail API usage or cost.
- Incomplete or misleading detections and correlation claims.
- Accidental exposure of production logs, account identifiers or credentials in Git.

## Controls implemented

- Server binds to loopback by default and startup rejects non-loopback bind addresses, preventing accidental unauthenticated LAN/public exposure.
- JSON request body limit of 2 MiB and content-type validation.
- Origin validation on POST requests when an Origin header is present.
- Restrictive browser security headers and escaped text rendering in the UI.
- SQLite parameterized queries and transactional evidence writes.
- SHA-256 fingerprints for canonical event, finding and incident payloads.
- Synthetic fixtures use reserved sample account IDs, IP addresses and resource identifiers.
- Simulator performs no network or cloud API calls.
- AWS collector is disabled unless an explicit environment flag is set; collection is one-shot and read-only, uses the standard credential chain, limits lookback to 24 hours and caps pages per request.
- No automatic remediation or AWS write API is implemented.
- Optional inventory is gated by an explicit environment variable, restricted to selected list/describe APIs, limited to five explicit regions and two pages per operation.
- Optional Ed25519 evidence signatures require a password-encrypted private key and a separately trusted public key. Invalid bundles are refused before signing.
- Terraform roots remain separate and require explicit opt-in for resource creation.

## Residual risks and limitations

- Local users and processes with access to the machine can read or modify the SQLite database and local source.
- SHA-256 does not prove origin, provide trusted timestamps or prevent an attacker from replacing both data and digest. Detached signatures add signer-key integrity only when the public key is independently trusted; they do not authenticate the original AWS event source.
- Loopback-only access is not a substitute for authentication if the app is exposed or if other local processes are untrusted.
- Event-pattern detections can miss unsupported event shapes, services, data-plane activity and contextual attack signals.
- Actor/account/time correlation and graph edges are investigative hypotheses, not causal proof. Sequence hypotheses require an explicit correlation signal and are bounded to 24 hours when timestamps are valid.
- The optional collector reads management-event history only and is not a durable streaming audit pipeline.
- The optional inventory is partial metadata discovery. A truncated or untruncated response is not a complete organization-wide resource inventory.
- Fixture evaluation is hand-labelled and cannot establish production detection accuracy.
- Human review is required before acting on findings. No remediation is automated.