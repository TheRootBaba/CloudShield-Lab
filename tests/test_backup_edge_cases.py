import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloudshield.backup import backup_database, verify_backup, restore_backup


class _Cursor:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return (self.value,)


class _SourceConnection:
    def __init__(self, error=None):
        self.error = error
        self.closed = False

    def backup(self, target):
        if self.error:
            raise self.error

    def close(self):
        self.closed = True


class _TargetConnection:
    def __init__(self, integrity="ok"):
        self.integrity = integrity
        self.closed = False

    def execute(self, statement):
        return _Cursor(self.integrity)

    def close(self):
        self.closed = True


class BackupEdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source.sqlite3"
        db = sqlite3.connect(self.source)
        db.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO records(value) VALUES ('evidence')")
        db.commit()
        db.close()
        self.backup = self.root / "backup.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def test_missing_source_and_backup_integrity_failure_cleanup(self):
        with self.assertRaises(FileNotFoundError):
            backup_database(self.root / "missing.sqlite3", self.backup)
        source = _SourceConnection()
        target = _TargetConnection("corrupt")
        with patch("cloudshield.backup.sqlite3.connect", side_effect=[source, target]):
            with self.assertRaisesRegex(RuntimeError, "integrity"):
                backup_database(self.source, self.backup)
        self.assertTrue(source.closed and target.closed)
        self.assertFalse(self.backup.exists())

    def test_backup_sqlite_error_closes_both_handles_and_removes_partial_file(self):
        source = _SourceConnection(sqlite3.OperationalError("simulated backup failure"))
        target = _TargetConnection()
        with patch("cloudshield.backup.sqlite3.connect", side_effect=[source, target]):
            with self.assertRaises(sqlite3.OperationalError):
                backup_database(self.source, self.backup)
        self.assertTrue(source.closed and target.closed)
        self.assertFalse(self.backup.exists())

    def test_manifest_write_failure_cleans_backup_and_manifest(self):
        original_open = Path.open

        def fail_manifest(path, *args, **kwargs):
            if path.name.endswith(".manifest.json"):
                raise OSError("simulated disk failure")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", fail_manifest):
            with self.assertRaises(OSError):
                backup_database(self.source, self.backup)
        self.assertFalse(self.backup.exists())
        self.assertFalse(Path(str(self.backup) + ".manifest.json").exists())

    def test_permission_mode_failure_is_non_fatal(self):
        with patch("cloudshield.backup.os.chmod", side_effect=OSError("ACL not supported")):
            result = backup_database(self.source, self.backup)
        self.assertEqual("ok", result["sqlite_integrity_check"])
        self.assertTrue(verify_backup(self.backup)["valid"])

    def test_verify_missing_malformed_wrong_shape_and_custom_manifest(self):
        self.assertFalse(verify_backup(self.backup)["valid"])
        backup_database(self.source, self.backup)
        manifest = Path(str(self.backup) + ".manifest.json")
        manifest.write_text("{", encoding="utf-8")
        self.assertFalse(verify_backup(self.backup)["valid"])
        manifest.write_text("[]", encoding="utf-8")
        self.assertFalse(verify_backup(self.backup)["valid"])
        record = {
            "manifest_version": "1.0",
            "database_file": self.backup.name,
            "size_bytes": self.backup.stat().st_size,
            "sha256": "0" * 64,
        }
        custom = self.root / "custom-manifest.json"
        custom.write_text(json.dumps(record), encoding="utf-8")
        result = verify_backup(self.backup, custom)
        self.assertFalse(result["valid"])
        self.assertTrue(any("SHA-256" in error for error in result["errors"]))

    def test_verify_rejects_unsupported_version_filename_and_size(self):
        backup_database(self.source, self.backup)
        manifest = Path(str(self.backup) + ".manifest.json")
        record = json.loads(manifest.read_text(encoding="utf-8"))
        record.update({"manifest_version": "99", "database_file": "other.sqlite3", "size_bytes": -1})
        manifest.write_text(json.dumps(record), encoding="utf-8")
        errors = verify_backup(self.backup)["errors"]
        self.assertTrue(any("version" in error.lower() for error in errors))
        self.assertTrue(any("filename" in error.lower() for error in errors))
        self.assertTrue(any("size" in error.lower() for error in errors))

    def test_restore_copy_and_integrity_failures_remove_partial_destination(self):
        backup_database(self.source, self.backup)
        copy_target = self.root / "copy-failure.sqlite3"
        with patch("cloudshield.backup.shutil.copyfile", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                restore_backup(self.backup, copy_target)
        self.assertFalse(copy_target.exists())
        corrupt_target = self.root / "integrity-failure.sqlite3"
        with patch("cloudshield.backup._integrity", side_effect=["ok", "broken"]):
            with self.assertRaisesRegex(RuntimeError, "integrity"):
                restore_backup(self.backup, corrupt_target)
        self.assertFalse(corrupt_target.exists())


if __name__ == "__main__":
    unittest.main()
