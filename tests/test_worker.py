import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudshield.worker import _inventory_due, _mark_inventory, _record_heartbeat, collect_workspace


class WorkerTests(unittest.TestCase):
    def test_inventory_schedule_is_independent_per_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "tenant.sqlite3"
            self.assertTrue(_inventory_due(db, "aws"))
            _mark_inventory(db, "aws")
            self.assertFalse(_inventory_due(db, "aws"))
            self.assertTrue(_inventory_due(db, "azure"))

    def test_heartbeat_is_written_to_auth_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "auth.sqlite3"
            _record_heartbeat(db)
            conn = sqlite3.connect(db)
            try:
                row = conn.execute("SELECT heartbeat_at FROM worker_heartbeat WHERE worker_id='primary'").fetchone()
            finally:
                conn.close()
            self.assertIsNotNone(row)
            self.assertTrue(row[0].endswith("Z"))

    def test_unconfigured_workspace_does_not_attempt_live_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "tenant.sqlite3"
            self.assertEqual(collect_workspace(db), {})


if __name__ == "__main__":
    unittest.main()
