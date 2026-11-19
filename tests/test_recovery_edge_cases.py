import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from cloudshield.auth import AuthStore
from cloudshield.recovery import backup_workspace_set, verify_workspace_backup, restore_workspace_set
import cloudshield.recovery as recovery


class RecoveryEdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.auth = self.root / "auth.sqlite3"
        self.tenants = self.root / "tenants"
        self.store = AuthStore(self.auth, self.tenants)
        user = self.store.register("admin@example.test", "Admin", "a sufficiently strong passphrase")
        self.store.tenant_path(user["tenant_id"]).touch()
        self.archive = self.root / "workspaces.zip"

    def tearDown(self):
        self.temp.cleanup()

    def _sidecar(self, archive):
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        Path(str(archive) + ".manifest.json").write_text(json.dumps({
            "manifest_version": "1.0", "archive_file": archive.name,
            "size_bytes": archive.stat().st_size, "sha256": digest, "database_count": 1
        }), encoding="utf-8")

    def test_backup_preconditions_and_overwrite_refusal(self):
        with self.assertRaises(FileNotFoundError):
            recovery.backup_workspace_set(self.root / "missing.sqlite3", self.tenants, self.archive)
        with self.assertRaises(FileNotFoundError):
            recovery.backup_workspace_set(self.auth, self.root / "missing-tenants", self.archive)
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(ValueError):
            recovery.backup_workspace_set(self.auth, empty, self.archive)
        backup_workspace_set(self.auth, self.tenants, self.archive)
        with self.assertRaises(FileExistsError):
            backup_workspace_set(self.auth, self.tenants, self.archive)

    def test_verify_missing_unreadable_and_unsupported_manifests(self):
        self.assertFalse(verify_workspace_backup(self.root / "missing.zip")["valid"])
        self.archive.write_bytes(b"not a zip")
        Path(str(self.archive) + ".manifest.json").write_text("{", encoding="utf-8")
        self.assertFalse(verify_workspace_backup(self.archive)["valid"])
        Path(str(self.archive) + ".manifest.json").write_text("[]", encoding="utf-8")
        self.assertFalse(verify_workspace_backup(self.archive)["valid"])

    def test_verify_rejects_wrong_outer_metadata_and_missing_internal_manifest(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("auth.sqlite3", b"not-a-db")
        self._sidecar(self.archive)
        sidecar_path = Path(str(self.archive) + ".manifest.json")
        sidecar = json.loads(sidecar_path.read_text())
        sidecar["archive_file"] = "renamed.zip"
        sidecar["size_bytes"] += 1
        sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
        result = verify_workspace_backup(self.archive)
        self.assertFalse(result["valid"])
        self.assertTrue(any("filename" in error.lower() for error in result["errors"]))
        self.assertTrue(any("size" in error.lower() for error in result["errors"]))
        self.assertTrue(any("internal workspace manifest" in error.lower() for error in result["errors"]))

    def test_verify_rejects_unsafe_archive_member(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("../escape.txt", "unsafe")
            archive.writestr("workspace-manifest.json", json.dumps({"manifest_version":"1.0","files":[]}))
        self._sidecar(self.archive)
        result = verify_workspace_backup(self.archive)
        self.assertFalse(result["valid"])
        self.assertTrue(any("unsafe" in error.lower() for error in result["errors"]))

    def test_verify_rejects_windows_drive_and_unexpected_archive_paths(self):
        for member in ("C:/Windows/Temp/escape.sqlite3", "tenants/./" + ("a" * 64) + ".sqlite3", "tenants/not-a-tenant.sqlite3", "secrets.txt"):
            with self.subTest(member=member):
                with zipfile.ZipFile(self.archive, "w") as archive:
                    archive.writestr(member, b"not a database")
                    archive.writestr("workspace-manifest.json", json.dumps({
                        "manifest_version": "1.0", "files": []
                    }))
                self._sidecar(self.archive)
                result = verify_workspace_backup(self.archive)
                self.assertFalse(result["valid"])
                self.assertTrue(any("unsafe" in error.lower() for error in result["errors"]))
                self.archive.unlink()
                Path(str(self.archive) + ".manifest.json").unlink()

    def test_manifest_write_failure_removes_partial_archive(self):
        original_open = Path.open
        def fail_outer_manifest(path, *args, **kwargs):
            if path.name.endswith(".zip.manifest.json"):
                raise OSError("simulated sidecar disk failure")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", fail_outer_manifest):
            with self.assertRaises(OSError):
                backup_workspace_set(self.auth, self.tenants, self.archive)
        self.assertFalse(self.archive.exists())
        self.assertFalse(Path(str(self.archive) + ".manifest.json").exists())

    def test_restore_integrity_failure_cleans_partial_destination(self):
        backup_workspace_set(self.auth, self.tenants, self.archive)
        destination = self.root / "restore-failed"
        # Two checks happen during archive verification; fail the first post-copy check.
        with patch("cloudshield.recovery._integrity", side_effect=["ok", "ok", "corrupt"]):
            with self.assertRaises(RuntimeError):
                restore_workspace_set(self.archive, destination)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
