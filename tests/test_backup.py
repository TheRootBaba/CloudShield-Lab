import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from cloudshield.backup import backup_database, verify_backup, restore_backup

class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source.sqlite3"
        db = sqlite3.connect(self.source)
        db.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO evidence(value) VALUES ('preserve-me')")
        db.commit(); db.close()
    def tearDown(self): self.temp.cleanup()
    def test_backup_verify_restore_round_trip(self):
        backup = self.root / "backup.sqlite3"
        result = backup_database(self.source, backup)
        self.assertEqual("ok", result["sqlite_integrity_check"])
        self.assertTrue(verify_backup(backup)["valid"])
        restored = self.root / "restored.sqlite3"
        self.assertTrue(restore_backup(backup, restored)["restored"])
        db = sqlite3.connect(restored)
        try: self.assertEqual("preserve-me", db.execute("SELECT value FROM evidence").fetchone()[0])
        finally: db.close()
    def test_tampering_and_manifest_mismatch_are_rejected(self):
        backup = self.root / "backup.sqlite3"
        backup_database(self.source, backup)
        with backup.open("ab") as stream: stream.write(b"tamper")
        result = verify_backup(backup)
        self.assertFalse(result["valid"])
        self.assertIn("Backup size mismatch", result["errors"])
        with self.assertRaises(ValueError): restore_backup(backup, self.root / "bad-restore.sqlite3")
    def test_refuses_overwrite(self):
        backup = self.root / "backup.sqlite3"
        backup_database(self.source, backup)
        with self.assertRaises(FileExistsError): backup_database(self.source, backup)
        with self.assertRaises(FileExistsError): restore_backup(backup, self.source)

if __name__ == "__main__": unittest.main()
