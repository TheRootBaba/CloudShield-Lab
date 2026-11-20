import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudshield.worker_coordination import (
    acquire_lease, renew_lease, release_lease, record_heartbeat, increment_counter, metrics_snapshot,
)


class WorkerCoordinationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "auth.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_one_worker_owns_unexpired_tenant_lease(self):
        self.assertTrue(acquire_lease(self.db, "collect:tenant-a", "worker-a", 60))
        self.assertFalse(acquire_lease(self.db, "collect:tenant-a", "worker-b", 60))
        self.assertFalse(release_lease(self.db, "collect:tenant-a", "worker-b"))
        self.assertTrue(release_lease(self.db, "collect:tenant-a", "worker-a"))
        self.assertTrue(acquire_lease(self.db, "collect:tenant-a", "worker-b", 60))

    def test_lease_renews_only_for_current_unexpired_owner(self):
        self.assertTrue(acquire_lease(self.db, "collect:tenant-a", "worker-a", 30))
        self.assertTrue(renew_lease(self.db, "collect:tenant-a", "worker-a", 60))
        self.assertFalse(renew_lease(self.db, "collect:tenant-a", "worker-b", 60))
        self.assertTrue(release_lease(self.db, "collect:tenant-a", "worker-a"))
        self.assertFalse(renew_lease(self.db, "collect:tenant-a", "worker-a", 60))

    def test_lease_expires_and_can_be_reclaimed(self):
        acquire_lease(self.db, "collect:tenant-a", "worker-a", 15)
        db = sqlite3.connect(self.db)
        try:
            db.execute("UPDATE worker_leases SET expires_at='2000-01-01T00:00:00+00:00'")
            db.commit()
        finally:
            db.close()
        self.assertTrue(acquire_lease(self.db, "collect:tenant-a", "worker-b", 30))

    def test_heartbeats_and_counters_are_service_scoped(self):
        record_heartbeat(self.db, "worker-a")
        record_heartbeat(self.db, "worker-b")
        increment_counter(self.db, "worker_cycles_total", 2)
        increment_counter(self.db, "worker_cycles_total", 3)
        self.assertEqual(metrics_snapshot(self.db), {"worker_cycles_total": 5})
        db = sqlite3.connect(self.db)
        try:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM worker_heartbeats").fetchone()[0], 2)
        finally:
            db.close()

    def test_invalid_lease_and_counter_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            acquire_lease(self.db, "", "worker", 60)
        with self.assertRaises(ValueError):
            increment_counter(self.db, "bad-name!", 1)


if __name__ == "__main__":
    unittest.main()
