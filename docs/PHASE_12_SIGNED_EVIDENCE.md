# Phase 12 — detached signed evidence bundles

## What is included
CloudShield can optionally sign an already-valid Phase 10 JSON evidence bundle with Ed25519. Private keys are encrypted at rest using a password-protected PKCS#8 PEM file. A detached JSON signature sidecar records the algorithm, bundle digest, public-key fingerprint and signature. Verification requires a separately supplied public key.

## Install and use
```powershell
python -m pip install -e ".[signing]"
cloudshield keygen --private-key artifacts/cloudshield-signing-private.pem --public-key artifacts/cloudshield-signing-public.pem
cloudshield sign-bundle artifacts/incident-evidence.json --private-key artifacts/cloudshield-signing-private.pem
cloudshield verify-signature artifacts/incident-evidence.json --public-key artifacts/cloudshield-signing-public.pem
```

The key-generation command prompts twice for a password (minimum 12 characters); signing prompts for it again. The detached signature defaults to `<bundle>.sig.json`.

## Trust and key handling
- Distribute the public key and its SHA-256 fingerprint through a separate trusted channel.
- Keep the encrypted private key and its password separate; restrict filesystem access and maintain a protected backup.
- Verification checks the bundle's Phase 10 hashes and the Ed25519 signature. It proves the bundle was signed by the holder of the corresponding private key, assuming the public key is trusted.
- A signature does not prove the original telemetry was truthful, complete or collected from AWS; it does not add a trusted timestamp, external notarization or immutable storage.
- Do not commit private keys, passwords or real customer evidence to Git.
