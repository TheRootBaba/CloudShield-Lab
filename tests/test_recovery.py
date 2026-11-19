import json
import tempfile
import unittest
from pathlib import Path

from cloudshield.auth import AuthStore
from cloudshield.recovery import backup_workspace_set, verify_workspace_backup, restore_workspace_set
from cloudshield.storage import EvidenceStore
from cloudshield.simulator import simulate


class WorkspaceRecoveryTests(unittest.TestCase):
    def test_backup_restore_preserves_authentication_and_tenant_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth_path = root / "auth.sqlite3"
            tenant_dir = root / "tenants"
            store = AuthStore(auth_path, tenant_dir)
            user = store.register("admin@example.test", "Admin", "a sufficiently strong passphrase", "Recovery Lab")
            session, token = store.login("admin@example.test", "a sufficiently strong passphrase")
            tenant_db = store.tenant_path(user["tenant_id"])
            payload = simulate("multi-stage-compromise")
            EvidenceStore(tenant_db).ingest(payload["events"])
            archive = root / "recovery" / "cloudshield-workspaces.zip"
            created = backup_workspace_set(auth_path, tenant_dir, archive)
            self.assertEqual(2, created["database_count"])
            self.assertTrue(verify_workspace_backup(archive)["valid"])
            restored = root / "restored"
            result = restore_workspace_set(archive, restored)
            self.assertTrue(result["restored"])
            restored_auth = AuthStore(restored / "auth.sqlite3", restored / "tenants")
            restored_session = restored_auth.get_session(token)
            self.assertIsNotNone(restored_session)
            self.assertEqual(session.tenant_id, restored_session.tenant_id)
            restored_db = restored_auth.tenant_path(user["tenant_id"])
            with EvidenceStore(restored_db)._connect() as db:
                self.assertEqual(4, db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_archive_tampering_is_detected_and_restore_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth_path = root / "auth.sqlite3"
            tenant_dir = root / "tenants"
            store = AuthStore(auth_path, tenant_dir)
            user = store.register("admin@example.test", "Admin", "a sufficiently strong passphrase")
            EvidenceStore(store.tenant_path(user["tenant_id"]))
            archive = root / "workspaces.zip"
            backup_workspace_set(auth_path, tenant_dir, archive)
            data = bytearray(archive.read_bytes())
            data[-20] ^= 0x01
            archive.write_bytes(data)
            self.assertFalse(verify_workspace_backup(archive)["valid"])
            with self.assertRaises(ValueError):
                restore_workspace_set(archive, root / "restore")

    def test_restore_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth_path = root / "auth.sqlite3"
            tenant_dir = root / "tenants"
            store = AuthStore(auth_path, tenant_dir)
            user = store.register("admin@example.test", "Admin", "a sufficiently strong passphrase")
            EvidenceStore(store.tenant_path(user["tenant_id"]))
            archive = root / "workspaces.zip"
            backup_workspace_set(auth_path, tenant_dir, archive)
            destination = root / "restore"
            destination.mkdir()
            with self.assertRaises(FileExistsError):
                restore_workspace_set(archive, destination)


if __name__ == "__main__":
    unittest.main()
