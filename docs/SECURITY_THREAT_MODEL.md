# Application security threat model

**Status:** local mode plus optional multi-user browser authentication and tenant-isolated evidence stores are implemented; not a certification or independent assessment.

## Assets and trust boundaries

- Security evidence, findings, incidents, workflow notes and signing metadata in the SQLite database and exported bundles.
- Optional AWS credentials remain outside CloudShield and are resolved only by the AWS SDK credential chain.
- API callers, imported JSON, browser requests, local filesystem users and any reverse proxy are separate trust boundaries.
- The database and signing private keys are operator-managed files. Anyone with filesystem access can read or alter them; local API controls do not defend against a compromised host or privileged local user.

## Threats and mitigations

| Threat | Controls | Residual risk |
|---|---|---|
| Unauthenticated API access | Multi-user mode uses scrypt password hashes, opaque server-side session hashes, 12-hour expiry, HttpOnly/SameSite cookies, logout/member revocation and CSRF validation; legacy bearer-token mode remains optional | No MFA/WebAuthn, SSO, email verification or self-service recovery; no independent penetration test |
| Privilege escalation | Server-enforced analyst/responder/admin roles; authenticated tenant scope selects a separate SQLite database; workspace invitations are single-use; member disable revokes sessions; shared cloud collectors are blocked in multi-user mode | One account belongs to one workspace; no cross-workspace switching; tenant isolation still needs independent security review |
| CSRF/cross-origin writes | Multi-user cookie sessions require matching CSRF cookie/header hashes and reject mismatched Origin; SameSite=Strict; no credentialed CORS | Same-origin XSS can still act as the signed-in user; CSP permits inline styles; frontend dependency review remains required |
| Request abuse | 2 MiB JSON body cap, JSON object validation, transfer-encoding rejection, per-IP sliding-window limits and auth-attempt throttling; persistent 15-minute account lock after eight failed password attempts | In-memory limits reset on restart and are per-process; proxy must add connection/time limits and global throttling |
| Evidence tampering | SHA-256 per-record and manifest checks; Ed25519 detached signatures; independently trusted public-key fingerprint | Hashes alone are not authenticity; key custody and trusted timestamping remain external |
| Sensitive changes repudiation | Tenant SQLite audit entries for workflow changes, notes, ingest, simulation and response lifecycle; central auth audit records account/session/invitation/member changes | Local DB administrator can alter audit rows; no external append-only sink |
| Unauthorized cloud response | Dry-run plan digest, independent request approval, two additional distinct admin approvals, service-wide default-on kill switch, tenant admins can only enable the stop switch, local-operator CLI confirmation required to disable, idempotency and no installed production adapter | Provider-specific writes and rollback are not implemented or accepted; never enable execution in production |
| Worker duplication | Per-workspace lease with owner checks, expiry/reclaim, per-worker heartbeat and operational counters | SQLite lease coordination requires one reliable shared volume; no multi-host or multi-region guarantee |
| Browser attacks | CSP, nosniff, frame denial, referrer and permissions policies, no-store | Inline styles remain permitted; dependency and browser review still required |
| Secret disclosure | no secret values logged; tokens supplied through environment; private signing keys excluded from Git | Environment variables may be visible to privileged host/process inspection; use an OS secret store for managed deployments |
| Supply-chain compromise | npm audit in CI; Python dependency audit job; pinned lockfile for JS | CI scan cannot prove transitive packages safe; review advisories and lockfile changes |

## Roles

- **analyst:** read workspace evidence and verify uploaded bundles; cannot mutate incidents or ingest data.
- **responder:** analyst access plus workflow changes, notes, ingest and offline simulation.
- **admin:** responder access plus workspace invitations, member revocation and isolated workspace creation. Cloud collectors are deliberately blocked in shared multi-user mode until provider credentials are tenant-scoped.

Configure unique `CLOUDSHIELD_ADMIN_TOKEN`, `CLOUDSHIELD_RESPONDER_TOKEN`, and optionally `CLOUDSHIELD_ANALYST_TOKEN`; each must be at least 32 characters. Do not commit tokens. When none are configured, the service operates in legacy loopback-only local mode; this is not authenticated remote access.

## Deployment boundary

The native default remains loopback-only. The separate production Compose profile places Caddy on ports 80/443 and keeps the Python API private on a Docker bridge. Startup refuses non-loopback binds unless multi-user auth and Secure cookies are enabled. Caddy must terminate HTTPS; the production sample uses automatic certificate management. The profile is a single-host template and has not been deployed to a real DNS name/host. Do not expose the API container port directly.

## Incident response

On suspected token compromise, stop the service, rotate the affected environment token, review host and SQLite audit logs, preserve the database and signing artifacts, verify exported bundles against independently stored public keys, and rebuild from a reviewed commit. A compromised host invalidates trust in local audit records and private keys.

## Explicit non-goals

No SSO, MFA/WebAuthn, verified email, password reset, session/device management UI, distributed rate limiting, immutable external audit sink, external KMS, trusted timestamp authority, penetration test or independent security sign-off is claimed.


## Cloud provider credential boundary

AWS uses the standard boto3 credential chain; Azure uses `DefaultAzureCredential`. CloudShield does not accept or persist provider client secrets. Collector execution is disabled unless its provider-specific environment flag is set, API collector routes require the admin role in legacy token mode. They are blocked in shared multi-user mode until per-tenant provider identities are supported. All adapter calls are read-only and bounded. Host environment variables, local CLI sessions, managed identities and cloud SDK credential caches remain trusted computing-base inputs. Never run with Owner/Administrator/Contributor permissions. Revoke temporary credentials after validation and protect exported telemetry as potentially sensitive.

## Container boundary

The supplied Compose profile runs as non-root with a read-only root filesystem, dropped capabilities, no-new-privileges and a persistent data volume. The host port is explicitly bound to loopback. The production profile adds browser password/session auth and tenant database isolation. MFA/SSO and independent tenant-isolation review remain outstanding; local containerization does not authorize network exposure.
