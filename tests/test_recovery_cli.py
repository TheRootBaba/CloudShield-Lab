import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cloudshield.auth import AuthStore
from cloudshield.storage import EvidenceStore
from cloudshield.simulator import simulate


class WorkspaceRecoveryCliTests(unittest.TestCase):
    def test_backup_verify_restore_commands_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            auth_path, tenant_dir = root / "auth.sqlite3", root / "tenants"
            auth = AuthStore(auth_path, tenant_dir)
            user = auth.register("ops@example.test", "Ops", "a sufficiently strong passphrase")
            session, token = auth.login("ops@example.test", "a sufficiently strong passphrase")
            EvidenceStore(auth.tenant_path(user["tenant_id"])).ingest(simulate("multi-stage-compromise")["events"])
            archive, restored = root / "backup.zip", root / "restored"
            def command(*args):
                result = subprocess.run([sys.executable, "-m", "cloudshield.cli", *map(str, args)],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                return json.loads(result.stdout)
            created = command("backup-workspaces", "--auth-database", auth_path,
                              "--tenant-directory", tenant_dir, "--output", archive)
            self.assertEqual(2, created["database_count"])
            self.assertTrue(command("verify-workspaces", archive)["valid"])
            self.assertTrue(command("restore-workspaces", archive, "--destination", restored)["restored"])
            recovered = AuthStore(restored / "auth.sqlite3", restored / "tenants")
            self.assertEqual(session.user_id, recovered.get_session(token).user_id)
            with EvidenceStore(recovered.tenant_path(user["tenant_id"]))._connect() as db:
                self.assertEqual(4, db.execute("SELECT COUNT(*) FROM events").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
