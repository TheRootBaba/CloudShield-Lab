"""Detached Ed25519 signatures for portable CloudShield evidence bundles."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .evidence_bundle import canonical, verify_bundle


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
    except ImportError as exc:
        raise RuntimeError("Evidence signing requires cryptography. Install with: pip install -e .[signing]") from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey, BestAvailableEncryption, NoEncryption


def _fingerprint(public_bytes: bytes) -> str:
    return hashlib.sha256(public_bytes).hexdigest()


def generate_keypair(private_path: str | Path, public_path: str | Path, password: str) -> dict[str, str]:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Private-key password must contain at least 12 characters")
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("Refusing to overwrite an existing signing key")
    if private_path.resolve() == public_path.resolve():
        raise ValueError("Private and public key paths must be different")
    serialization, private_cls, _, encrypt, _ = _crypto()
    private_key = private_cls.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encrypt(password.encode("utf-8")),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids clobbering a key created concurrently.
    with private_path.open("xb") as handle:
        handle.write(private_bytes)
    try:
        with public_path.open("xb") as handle:
            handle.write(public_bytes)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    return {"algorithm": "Ed25519", "public_key_sha256": _fingerprint(public_bytes)}


def sign_bundle(bundle: dict[str, Any], private_path: str | Path, password: str) -> dict[str, str]:
    verification = verify_bundle(bundle)
    if not verification["valid"]:
        raise ValueError("Refusing to sign an invalid evidence bundle: " + "; ".join(verification["errors"]))
    serialization, _, _, _, _ = _crypto()
    try:
        private_key = serialization.load_pem_private_key(
            Path(private_path).read_bytes(), password=password.encode("utf-8")
        )
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("Unable to load encrypted private signing key") from exc
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Signing key must be Ed25519")
    payload = canonical(bundle).encode("utf-8")
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "signature_version": "1.0",
        "algorithm": "Ed25519",
        "bundle_sha256": verification["bundle_sha256"],
        "public_key_sha256": _fingerprint(public_bytes),
        "signature": base64.b64encode(private_key.sign(payload)).decode("ascii"),
    }


def verify_signature(bundle: dict[str, Any], signature: dict[str, Any], public_path: str | Path) -> dict[str, Any]:
    bundle_check = verify_bundle(bundle)
    errors = list(bundle_check["errors"])
    if not bundle_check["valid"]:
        return {"valid": False, "errors": errors, "bundle_valid": False, "signature_valid": False}
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        return {"valid": False, "errors": ["Unsupported or missing signature algorithm"], "bundle_valid": True, "signature_valid": False}
    serialization, _, public_cls, _, _ = _crypto()
    try:
        public_bytes = Path(public_path).read_bytes()
        public_key = serialization.load_pem_public_key(public_bytes)
        if not isinstance(public_key, public_cls):
            raise ValueError("Public key must be Ed25519")
        if _fingerprint(public_bytes) != signature.get("public_key_sha256"):
            raise ValueError("Public key fingerprint mismatch")
        if signature.get("bundle_sha256") != bundle_check["bundle_sha256"]:
            raise ValueError("Signature references a different bundle digest")
        payload = canonical(bundle).encode("utf-8")
        public_key.verify(base64.b64decode(signature.get("signature", ""), validate=True), payload)
    except Exception as exc:
        errors.append(f"Signature verification failed: {type(exc).__name__}")
        return {"valid": False, "errors": errors, "bundle_valid": True, "signature_valid": False}
    return {
        "valid": True,
        "errors": [],
        "bundle_valid": True,
        "signature_valid": True,
        "bundle_sha256": bundle_check["bundle_sha256"],
        "public_key_sha256": signature["public_key_sha256"],
    }


def sign_bundle_file(bundle_path: str | Path, private_path: str | Path, signature_path: str | Path, password: str):
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    signature = sign_bundle(bundle, private_path, password)
    bundle_path = Path(bundle_path)
    signature_path = Path(signature_path)
    if bundle_path.resolve() == signature_path.resolve():
        raise ValueError("Signature sidecar must not overwrite the evidence bundle")
    with signature_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(signature, indent=2) + "\n")
    return signature


def verify_signature_files(bundle_path: str | Path, signature_path: str | Path, public_path: str | Path):
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    signature = json.loads(Path(signature_path).read_text(encoding="utf-8"))
    return verify_signature(bundle, signature, public_path)
