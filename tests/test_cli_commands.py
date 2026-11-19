import contextlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloudshield import cli
from cloudshield.auth import AuthStore
from cloudshield.storage import EvidenceStore


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "fixtures" / "sample_cloudtrail.json"


class CliCommandCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main([str(arg) for arg in args])
        value = json.loads(output.getvalue()) if output.getvalue().strip() else None
        return code, value

    def test_analyze_simulate_investigate_and_input_errors(self):
        code, analyzed = self.run_cli("analyze", SAMPLE)
        self.assertEqual(0, code)
        self.assertEqual("sample_cloudtrail.json", analyzed["input_file"])
        code, simulated = self.run_cli("simulate", "multi-stage-compromise", "--output", self.root / "nested" / "simulation.json")
        self.assertEqual(0, code)
        self.assertTrue((self.root / "nested" / "simulation.json").is_file())
        self.assertEqual("multi-stage-compromise", simulated["scenario"])
        code, investigation = self.run_cli("investigate", SAMPLE, "demo-iam-001")
        self.assertEqual(0, code)
        self.assertTrue(investigation)
        with self.assertRaises(SystemExit):
            self.run_cli("investigate", SAMPLE, "not-present")
        with self.assertRaises(SystemExit):
            cli._read(self.root / "missing.json")

    def test_store_timeline_and_incident_commands(self):
        database = self.root / "store" / "evidence.sqlite3"
        code, stored = self.run_cli("store", SAMPLE, "--database", database)
        self.assertEqual(0, code)
        self.assertGreater(stored["events_inserted"], 0)
        code, all_events = self.run_cli("timeline", "--database", database)
        self.assertEqual(0, code)
        self.assertTrue(all_events)
        actor = all_events[0]["event"]["actor"]
        account_id = all_events[0]["event"]["account_id"]
        code, timeline = self.run_cli("timeline", "--database", database, "--actor", actor, "--account-id", account_id)
        self.assertEqual(0, code)
        self.assertTrue(timeline)
        db = sqlite3.connect(database)
        try:
            incident_id = db.execute("SELECT incident_id FROM incidents LIMIT 1").fetchone()[0]
        finally:
            db.close()
        code, incident = self.run_cli("incident", incident_id, "--database", database)
        self.assertEqual(0, code)
        self.assertTrue(incident)
        with self.assertRaises(SystemExit):
            self.run_cli("incident", "missing-incident", "--database", database)

    def test_evaluate_command_and_output_file(self):
        output = self.root / "reports" / "evaluation.json"
        code, result = self.run_cli("evaluate", ROOT / "fixtures" / "detection_evaluation.json", "--output", output)
        self.assertEqual(0, code)
        self.assertTrue(output.is_file())
        self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))

    def test_keygen_sign_and_verify_signature_commands(self):
        private_key, public_key = self.root / "private.pem", self.root / "public.pem"
        with patch("cloudshield.cli.getpass.getpass", side_effect=["a strong key password", "a strong key password"]):
            code, result = self.run_cli("keygen", "--private-key", private_key, "--public-key", public_key)
        self.assertEqual(0, code)
        self.assertTrue(private_key.is_file() and public_key.is_file())
        bundle = self.root / "bundle.json"
        bundle.write_text("{}", encoding="utf-8")
        signature = self.root / "bundle.sig.json"
        with patch("cloudshield.cli.getpass.getpass", return_value="a strong key password"), \
             patch("cloudshield.cli.sign_bundle_file", return_value={"valid": True}) as sign:
            code, signed = self.run_cli("sign-bundle", bundle, "--private-key", private_key, "--signature", signature)
        self.assertEqual(0, code)
        sign.assert_called_once()
        self.assertEqual(str(signature), signed["signature_file"])
        with patch("cloudshield.cli.verify_signature_files", return_value={"valid": True}):
            self.assertEqual(0, self.run_cli("verify-signature", bundle, "--public-key", public_key)[0])
        with patch("cloudshield.cli.verify_signature_files", return_value={"valid": False, "errors": ["bad signature"]}):
            self.assertEqual(1, self.run_cli("verify-signature", bundle, "--public-key", public_key)[0])

    def test_aws_inventory_requires_explicit_opt_in_and_writes_output(self):
        with patch.dict(os.environ, {"CLOUDSHIELD_ENABLE_AWS_INVENTORY": "0"}):
            with self.assertRaises(SystemExit):
                self.run_cli("aws-inventory", "--regions", "us-east-1")
        output = self.root / "aws" / "inventory.json"
        with patch.dict(os.environ, {"CLOUDSHIELD_ENABLE_AWS_INVENTORY": "1"}), \
             patch("cloudshield.aws_inventory.collect_inventory", return_value={"provider": "aws", "resources": []}) as collect:
            code, result = self.run_cli("aws-inventory", "--regions", "us-east-1", "--max-pages", "1", "--output", output)
        self.assertEqual(0, code)
        collect.assert_called_once_with(["us-east-1"], 1)
        self.assertEqual("aws", result["provider"])
        self.assertTrue(output.is_file())

    def test_azure_commands_require_opt_in_scope_and_cover_both_collectors(self):
        with patch.dict(os.environ, {"CLOUDSHIELD_ENABLE_AZURE_COLLECTION": "0", "AZURE_SUBSCRIPTION_ID": "sub"}):
            with self.assertRaises(SystemExit):
                self.run_cli("azure-inventory")
        with patch.dict(os.environ, {"CLOUDSHIELD_ENABLE_AZURE_COLLECTION": "1"}, clear=False):
            os.environ.pop("AZURE_SUBSCRIPTION_ID", None)
            with self.assertRaises(SystemExit):
                self.run_cli("azure-inventory")
        with patch.dict(os.environ, {"CLOUDSHIELD_ENABLE_AZURE_COLLECTION": "1", "AZURE_SUBSCRIPTION_ID": "sub"}), \
             patch("cloudshield.azure_provider.collect_inventory", return_value={"provider": "azure", "resources": []}) as collect:
            code, inventory = self.run_cli("azure-inventory", "--max-pages", "1", "--max-records", "10", "--output", self.root / "azure.json")
        self.assertEqual(0, code)
        collect.assert_called_once_with("sub", 1, 10)
        self.assertEqual("azure", inventory["provider"])
        event_result = {"provider": "azure", "events": [], "event_count": 0}
        with patch.dict(os.environ, {"CLOUDSHIELD_ENABLE_AZURE_COLLECTION": "1", "AZURE_SUBSCRIPTION_ID": "sub"}), \
             patch("cloudshield.azure_provider.collect_activity_logs", return_value=event_result) as collect_logs:
            code, logs = self.run_cli("azure-activity-logs", "--lookback-hours", "1", "--max-pages", "1", "--max-records", "10")
        self.assertEqual(0, code)
        collect_logs.assert_called_once_with("sub", 1, 1, 10)
        self.assertIn("analysis", logs)

    def test_single_database_backup_verify_and_restore_commands(self):
        source = self.root / "source.sqlite3"
        EvidenceStore(source).ingest(json.loads(SAMPLE.read_text(encoding="utf-8")))
        archive = self.root / "backup.sqlite3"
        self.assertEqual(0, self.run_cli("backup", "--database", source, "--output", archive)[0])
        self.assertTrue(self.run_cli("verify-backup", archive)[1]["valid"])
        destination = self.root / "restored.sqlite3"
        self.assertEqual(0, self.run_cli("restore-backup", archive, "--destination", destination)[0])
        self.assertTrue(destination.is_file())


if __name__ == "__main__":
    unittest.main()
