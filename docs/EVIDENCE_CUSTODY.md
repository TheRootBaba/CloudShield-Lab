# Evidence custody, verification and retention

## Bundle format 1.1

Exports include a versioned manifest, export timestamp, producer identity/version, collection metadata, referenced incident, workflow history, referenced events and findings. Each evidence record carries its SHA-256 digest; the manifest hashes the canonical bundle body. Verification rejects unknown bundle versions, malformed provenance, count/reference mismatches, duplicate event IDs and changed payloads.

The `collection_scope` explicitly limits the bundle to records referenced by the incident in the local database. `source_formats` records observed source-format labels; it does not independently authenticate the upstream collector or source.

## Independent verification

1. Preserve the JSON export and any detached `.sig.json` sidecar without editing either.
2. Obtain the Ed25519 public key and its SHA-256 fingerprint through a separate trusted channel.
3. Run `cloudshield verify-signature bundle.json --signature bundle.json.sig.json --public-key trusted-public.pem`.
4. Retain the verifier output, public-key fingerprint, bundle digest, operator identity and verification time in a separately controlled case record.
5. Treat any verification error as a failed verification; do not repair the original evidence file in place.

A bundle without a detached signature can be checked for internal consistency with `POST /api/evidence/verify` or the Python verifier, but the hashes are not proof of origin. Ed25519 verifies that a holder of the corresponding private key signed the exact bundle; it does not prove telemetry truth or trusted time.

## Key rotation

Generate a new encrypted Ed25519 key pair with a new key identifier recorded in the external key register. Publish and independently fingerprint the new public key before using it. During transition, verify historical signatures with the archived old public key and new exports with the new key. Revoke/mark the old key retired in the external register; never overwrite or silently replace historical public keys. Keep encrypted private keys offline or in an OS/hardware secret store, restrict file permissions and back up recovery material separately.

## Retention and deletion

No automatic retention or deletion scheduler is enabled. The operator is the data controller: define case/legal retention before importing real telemetry; export and verify required evidence; back up encrypted database copies; then delete the SQLite database, WAL/SHM companions, exported bundles and backups according to the approved schedule. Secure deletion cannot be guaranteed on SSDs, snapshots, cloud-sync folders or journaled filesystems. Document deletion date, scope and approver in the external case register. Do not delete evidence under legal hold.

## Trusted time and immutable custody

Trusted timestamping and immutable/WORM storage are design-only future integrations. A local `generated_at` value is a host clock claim, not a trusted timestamp. No external timestamp authority, transparency log or immutable remote archive is contacted or provisioned by this project.
