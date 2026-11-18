# Phase 10 — Portable evidence bundles and integrity verification

## Bundle contents
- Incident record and stored digest.
- Referenced normalized event records and their digests.
- Findings attached to those events and digests.
- Incident workflow state and activity history.
- Versioned manifest with counts and SHA-256 digest of the canonical bundle body.

## Features
- Export JSON from the incident investigation drawer.
- The export UI verifies the bundle before download.
- Evidence Vault can load a previously exported JSON bundle and verify it.
- Verifier checks individual incident/event/finding hashes, manifest digest and event references.

## API
- GET /api/incidents/{id}/export
- POST /api/evidence/verify

## Integrity boundaries
SHA-256 verification detects accidental or deliberate modification when compared with a known trusted digest. The manifest is not signed; it is stored alongside the bundle and therefore cannot establish authenticity on its own. No trusted timestamp, external custody service, signature, encryption or immutable storage is provided. Bundle contents may include sensitive audit data; treat exports as confidential.
