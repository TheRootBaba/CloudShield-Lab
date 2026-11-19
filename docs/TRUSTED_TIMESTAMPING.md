# Trusted timestamping and immutable evidence — design

## Current implementation

CloudShield evidence bundles include a versioned manifest, UTC export metadata, source/collection provenance, canonical SHA-256 digests and optional detached Ed25519 signatures. Verification is offline and requires the verifier to obtain the trusted public key independently. Local host time, private-key custody and the SQLite database remain operator-controlled.

## Optional RFC 3161 timestamp authority

A future timestamp integration should submit only the SHA-256 digest of the canonical bundle manifest to an independently operated RFC 3161 Time-Stamp Authority (TSA), not raw incident contents. Store the returned timestamp token as a detached sidecar. Verification must:

1. Recompute the bundle and manifest digest.
2. Validate the TSA response signature and message-imprint digest.
3. Validate the TSA certificate chain against an independently distributed trust store.
4. Validate timestamp policy OID, nonce (when used), accuracy and certificate validity/revocation according to the TSA policy.
5. Record TSA identity, policy, serial, generation time and verifier result.
6. Fail closed on an invalid token and distinguish “signature valid” from “timestamp trusted”.

## Immutable archive

An optional archive adapter should use retention-locked/WORM storage with object versioning, legal hold, access logging and independently administered retention policy. Uploads must be content-addressed and idempotent. Deletion should be impossible before retention expiry except through documented break-glass/legal processes. Verify an object after upload and periodically re-verify stored digests. Keep signing keys and trusted public-key registry outside the evidence archive.

## Release gate

No TSA endpoint, archive provider, credentials, retention period or legal policy is selected in this repository. Do not describe local SHA-256 or Ed25519 alone as trusted time or immutable custody. Select a provider and retention policy only after privacy, jurisdiction, cost, key custody and legal requirements are approved. No external timestamp or archive calls are made by current CloudShield code.
