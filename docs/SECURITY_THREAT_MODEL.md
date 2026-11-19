# Application security threat model

**Status:** implemented controls for a single-tenant local API; not a certification or independent assessment.

## Assets and trust boundaries

- Security evidence, findings, incidents, workflow notes and signing metadata in the SQLite database and exported bundles.
- Optional AWS credentials remain outside CloudShield and are resolved only by the AWS SDK credential chain.
- API callers, imported JSON, browser requests, local filesystem users and any reverse proxy are separate trust boundaries.
- The database and signing private keys are operator-managed files. Anyone with filesystem access can read or alter them; local API controls do not defend against a compromised host or privileged local user.

## Threats and mitigations

| Threat | Controls | Residual risk |
|---|---|---|
| Unauthenticated API access | Optional role-specific bearer tokens; 32-character minimum; constant-time comparisons; 401 on missing/invalid token when configured | Tokens are long-lived environment secrets; no user directory, MFA, token expiry or revocation database |
| Privilege escalation | analyst read/verify; responder workflow/ingest/simulation; admin AWS collector; deny by default for unknown roles | Single-tenant roles; no per-incident or tenant ACL |
| CSRF/cross-origin writes | Bearer header rather than ambient cookie; reject mismatched Origin; no credentialed CORS | Browser XSS or malicious same-origin code can still act with the token; frontend is not an identity provider |
| Request abuse | 2 MiB JSON body cap, JSON object validation, transfer-encoding rejection, per-IP sliding-window limits | In-memory limits reset on restart and are per-process; proxy must add connection/time limits and global throttling |
| Evidence tampering | SHA-256 per-record and manifest checks; Ed25519 detached signatures; independently trusted public-key fingerprint | Hashes alone are not authenticity; key custody and trusted timestamping remain external |
| Sensitive changes repudiation | SQLite audit entries for workflow changes, notes, ingest, simulation and collector invocation | Local DB administrator can alter audit rows; no external append-only sink |
| Browser attacks | CSP, nosniff, frame denial, referrer and permissions policies, no-store | Inline styles remain permitted; dependency and browser review still required |
| Secret disclosure | no secret values logged; tokens supplied through environment; private signing keys excluded from Git | Environment variables may be visible to privileged host/process inspection; use an OS secret store for managed deployments |
| Supply-chain compromise | npm audit in CI; Python dependency audit job; pinned lockfile for JS | CI scan cannot prove transitive packages safe; review advisories and lockfile changes |

## Roles

- **analyst:** read API and verify uploaded bundles; cannot mutate incidents or ingest data.
- **responder:** analyst access plus workflow changes, notes, ingest and offline simulation.
- **admin:** responder access plus explicitly enabled AWS collector endpoint.

Configure unique `CLOUDSHIELD_ADMIN_TOKEN`, `CLOUDSHIELD_RESPONDER_TOKEN`, and optionally `CLOUDSHIELD_ANALYST_TOKEN`; each must be at least 32 characters. Do not commit tokens. When none are configured, the service operates in legacy loopback-only local mode; this is not authenticated remote access.

## Deployment boundary

The Python server continues to bind only to loopback. For remote operator access, place a separately managed TLS reverse proxy / VPN in front of the loopback service, require HTTPS and inject the appropriate bearer token server-side. Do not expose the Python listener directly. The current React UI does not implement a login/token lifecycle, so a hosted interactive UI is not approved by this threat model; API token controls are not a complete hosted-user experience.

## Incident response

On suspected token compromise, stop the service, rotate the affected environment token, review host and SQLite audit logs, preserve the database and signing artifacts, verify exported bundles against independently stored public keys, and rebuild from a reviewed commit. A compromised host invalidates trust in local audit records and private keys.

## Explicit non-goals

No multi-tenancy, SSO, MFA, password reset, session cookies, CSRF cookie tokens, distributed rate limiting, immutable audit sink, external KMS, trusted timestamp authority, penetration test or independent security sign-off is claimed.
