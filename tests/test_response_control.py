import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cloudshield import cloud_ops
from cloudshield import response_control as rc
from cloudshield.cli import main as cli_main


class ResponseControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tenant_db = Path(self.tmp.name) / "tenant.sqlite3"
        self.auth_db = Path(self.tmp.name) / "auth.sqlite3"
        cloud_ops.ensure_schema(self.tenant_db)
        self.finding = {
            "event_id": "evt-response-1", "rule_id": "CS-IAM-002",
            "severity": "HIGH", "evidence": {"access_key_id": "AKIA-TEST-123", "user_name": "test-user"},
        }
        self.finding_id = hashlib.sha256(json.dumps(
            [self.finding["event_id"], self.finding["rule_id"]],
            sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        db = sqlite3.connect(self.tenant_db)
        try:
            db.execute("""CREATE TABLE findings (
                finding_id TEXT PRIMARY KEY,event_id TEXT,rule_id TEXT,
                payload_json TEXT,payload_sha256 TEXT)""")
            db.execute("INSERT INTO findings VALUES(?,?,?,?,?)", (
                self.finding_id, self.finding["event_id"], self.finding["rule_id"],
                json.dumps(self.finding), "digest"))
            db.commit()
        finally:
            db.close()
        self.request = cloud_ops.request_response(
            self.tenant_db, self.finding_id,
            "review_and_revoke_suspicious_credentials",
            "Validate the credential owner and preserve evidence.", "requester")
        cloud_ops.decide_response(
            self.tenant_db, self.request["request_id"], "initial-admin", True, "Approved for review")

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_is_deterministic_and_does_not_execute_provider_calls(self):
        cloud_ops.store_inventory(self.tenant_db, "aws", [
            {"resource_id": "AKIA-TEST-123", "resource_type": "access-key"}
        ])
        first = rc.dry_run(self.tenant_db, self.request["request_id"])
        second = rc.dry_run(self.tenant_db, self.request["request_id"])
        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertEqual(first["execution"], "not_performed")
        self.assertEqual(first["blast_radius"]["inventory_matches"], 1)
        self.assertEqual(first["blast_radius"]["unresolved_targets"], 0)

    def test_dry_run_requires_initial_approval(self):
        pending = cloud_ops.request_response(
            self.tenant_db, self.finding_id,
            "review_and_revoke_suspicious_credentials",
            "Second request after previous approval.", "requester-2")
        with self.assertRaises(PermissionError):
            rc.dry_run(self.tenant_db, pending["request_id"])

    def test_dry_run_marks_missing_action_parameters_and_targets_unresolved(self):
        finding = {"event_id":"evt-missing-params","rule_id":"CS-IAM-002",
                   "severity":"HIGH","evidence":{"request_parameters":{}}}
        finding_id = hashlib.sha256(json.dumps(
            [finding["event_id"], finding["rule_id"]],
            sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        db = sqlite3.connect(self.tenant_db)
        try:
            db.execute("INSERT INTO findings VALUES(?,?,?,?,?)", (
                finding_id, finding["event_id"], finding["rule_id"], json.dumps(finding), "digest-2"))
            db.commit()
        finally:
            db.close()
        request = cloud_ops.request_response(
            self.tenant_db, finding_id, "review_and_revoke_suspicious_credentials",
            "Missing key details must prevent execution.", "requester-2")
        cloud_ops.decide_response(self.tenant_db, request["request_id"], "initial-admin-2", True)
        plan = rc.dry_run(self.tenant_db, request["request_id"])
        self.assertFalse(plan["preconditions_met"])
        self.assertIn("user_name", plan["missing_action_parameters"])
        self.assertIn("access_key_id", plan["missing_action_parameters"])
        self.assertGreaterEqual(plan["blast_radius"]["unresolved_targets"], 1)

    def test_execution_requires_quorum_global_kill_switch_and_adapter(self):
        cloud_ops.store_inventory(self.tenant_db, "aws", [
            {"resource_id": "AKIA-TEST-123", "resource_type": "access-key"}
        ])
        plan = rc.dry_run(self.tenant_db, self.request["request_id"])
        with self.assertRaises(PermissionError):
            rc.approve_execution(self.tenant_db, self.request["request_id"], "requester")
        self.assertFalse(rc.approve_execution(
            self.tenant_db, self.request["request_id"], "approver-a")["quorum_met"])
        self.assertTrue(rc.approve_execution(
            self.tenant_db, self.request["request_id"], "approver-b")["quorum_met"])
        with patch.dict(os.environ, {"CLOUDSHIELD_RESPONSE_EXECUTION_ENABLED": "1"}):
            with self.assertRaises(PermissionError):
                rc.execute(self.tenant_db, self.request["request_id"], "idempotency-key-0001",
                           plan["plan_sha256"], control_path=self.auth_db)
            rc.set_kill_switch(self.auth_db, False, "security-admin", allow_disable=True)
            with self.assertRaises(RuntimeError):
                rc.execute(self.tenant_db, self.request["request_id"], "idempotency-key-0001",
                           plan["plan_sha256"], control_path=self.auth_db)
            sandbox_adapter = lambda **kwargs: {"ok": True, "operation_id": "sandbox-op-1",
                                                  "rollback": {"manual": "credential re-issue required"}}
            result = rc.execute(self.tenant_db, self.request["request_id"], "idempotency-key-0001",
                                plan["plan_sha256"], adapter=sandbox_adapter, control_path=self.auth_db)
            self.assertEqual(result["status"], "succeeded")
            self.assertTrue(result["rollback_available"])
            with self.assertRaises(ValueError):
                rc.execute(self.tenant_db, self.request["request_id"], "idempotency-key-0002",
                           plan["plan_sha256"], control_path=self.auth_db)

    def test_execution_rejects_requester_and_initial_approver_as_execution_approvers(self):
        plan = rc.dry_run(self.tenant_db, self.request["request_id"])
        for actor in ("requester", " REQUESTER ", "initial-admin", "INITIAL-ADMIN "):
            with self.assertRaises(PermissionError):
                rc.approve_execution(self.tenant_db, self.request["request_id"], actor)
        self.assertEqual(len(plan["plan_sha256"]), 64)

    def test_kill_switch_is_enabled_by_default_and_auditable(self):
        self.assertTrue(rc.kill_switch_state(self.auth_db))
        with self.assertRaises(PermissionError):
            rc.set_kill_switch(self.auth_db, False, "workspace-admin")
        state = rc.set_kill_switch(self.auth_db, False, "local-operator", allow_disable=True)
        self.assertEqual(state["kill_switch"], "disabled")
        self.assertFalse(rc.kill_switch_state(self.auth_db))
        state = rc.set_kill_switch(self.auth_db, True, "admin")
        self.assertEqual(state["kill_switch"], "enabled")
        self.assertTrue(rc.kill_switch_state(self.auth_db))

    def test_operator_cli_requires_exact_phrase_to_disable_and_can_reenable(self):
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli_main(["response-kill-switch", "--auth-database", str(self.auth_db), "--disable"])
            self.assertEqual(0, cli_main([
                "response-kill-switch", "--auth-database", str(self.auth_db),
                "--disable", "--confirm-disable", "DISABLE CLOUDSHIELD RESPONSE EXECUTION"
            ]))
            self.assertFalse(rc.kill_switch_state(self.auth_db))
            self.assertEqual(0, cli_main([
                "response-kill-switch", "--auth-database", str(self.auth_db), "--enable"
            ]))
        self.assertTrue(rc.kill_switch_state(self.auth_db))


if __name__ == "__main__":
    unittest.main()
