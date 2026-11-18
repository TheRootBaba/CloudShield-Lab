import json
import tempfile
import unittest
from pathlib import Path

from cloudshield.evidence_signing import (generate_keypair, sign_bundle, verify_signature,
                                           sign_bundle_file, verify_signature_files)
from cloudshield.evidence_bundle import build_bundle
from cloudshield.pipeline import analyze_payload
from cloudshield.simulator import simulate
from cloudshield.storage import EvidenceStore


class EvidenceSigningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "evidence.sqlite"
        payload = simulate("multi-stage-compromise", at="2026-11-18T10:00:00Z")["events"]
        EvidenceStore(self.db).ingest(payload)
        self.incident_id = analyze_payload(payload)["incidents"][0]["incident_id"]
        self.bundle = build_bundle(self.db, self.incident_id)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
        self.password = "correct horse battery staple"

    def tearDown(self):
        self.tmp.cleanup()

    def test_encrypted_ed25519_sign_and_verify(self):
        info = generate_keypair(self.private, self.public, self.password)
        self.assertEqual("Ed25519", info["algorithm"])
        signature = sign_bundle(self.bundle, self.private, self.password)
        result = verify_signature(self.bundle, signature, self.public)
        self.assertTrue(result["valid"])
        self.assertTrue(result["signature_valid"])

    def test_tampered_bundle_rejected_before_signature_validation(self):
        generate_keypair(self.private, self.public, self.password)
        signature = sign_bundle(self.bundle, self.private, self.password)
        tampered = json.loads(json.dumps(self.bundle))
        tampered["incident"]["data"]["actor"] = "tampered"
        result = verify_signature(tampered, signature, self.public)
        self.assertFalse(result["valid"])
        self.assertFalse(result["bundle_valid"])

    def test_wrong_public_key_rejected(self):
        generate_keypair(self.private, self.public, self.password)
        signature = sign_bundle(self.bundle, self.private, self.password)
        other_private = self.root / "other-private.pem"
        other_public = self.root / "other-public.pem"
        generate_keypair(other_private, other_public, self.password)
        result = verify_signature(self.bundle, signature, other_public)
        self.assertFalse(result["valid"])
        self.assertFalse(result["signature_valid"])

    def test_detached_signature_file_round_trip_and_no_overwrite(self):
        generate_keypair(self.private, self.public, self.password)
        bundle_path = self.root / "bundle.json"
        signature_path = self.root / "bundle.sig.json"
        bundle_path.write_text(json.dumps(self.bundle), encoding="utf-8")
        sign_bundle_file(bundle_path, self.private, signature_path, self.password)
        self.assertTrue(verify_signature_files(bundle_path, signature_path, self.public)["valid"])
        with self.assertRaises(FileExistsError):
            sign_bundle_file(bundle_path, self.private, signature_path, self.password)

    def test_invalid_bundle_cannot_be_signed(self):
        generate_keypair(self.private, self.public, self.password)
        bad = dict(self.bundle)
        bad["manifest"] = {}
        with self.assertRaises(ValueError):
            sign_bundle(bad, self.private, self.password)

    def test_keygen_refuses_overwrite_and_weak_password(self):
        with self.assertRaises(ValueError):
            generate_keypair(self.private, self.public, "weak")
        generate_keypair(self.private, self.public, self.password)
        with self.assertRaises(FileExistsError):
            generate_keypair(self.private, self.public, self.password)


if __name__ == "__main__":
    unittest.main()
