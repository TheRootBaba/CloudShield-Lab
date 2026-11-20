import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cloudshield import cloud_ops


class CloudOpsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "tenant.sqlite3"
        cloud_ops.ensure_schema(self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_aws_connection_is_workspace_local_and_external_id_only_returned_once(self):
        created = cloud_ops.configure_aws(self.db, "arn:aws:iam::123456789012:role/CloudShieldReadOnly", "us-east-1", "admin-a")
        self.assertEqual(len(created["external_id"]), 48)
        status = cloud_ops.get_connection(self.db, "aws")
        self.assertFalse(status["enabled"])
        self.assertNotIn("external_id", status)
        self.assertEqual(status["role_arn"], created["role_arn"])

    def test_aws_assume_role_uses_workspace_external_id_and_checks_account(self):
        created = cloud_ops.configure_aws(self.db, "arn:aws:iam::123456789012:role/CloudShieldReadOnly", "us-east-1", "admin")
        cloud_ops.mark_provider(self.db, "aws", status="connected")
        cloud_ops.set_enabled(self.db, "aws", True)
        class FakeSts:
            def __init__(self): self.request = None
            def assume_role(self, **kwargs):
                self.request = kwargs
                return {"Credentials":{"AccessKeyId":"A","SecretAccessKey":"B","SessionToken":"C"}}
        class FakeSession:
            def __init__(self, **kwargs): self.kwargs = kwargs
            def client(self, name, config=None):
                class Identity:
                    def get_caller_identity(self): return {"Account":"123456789012","Arn":"assumed-role"}
                return Identity()
        sts = FakeSts()
        session, config = cloud_ops.aws_session(self.db, sts_client=sts, session_factory=FakeSession)
        self.assertEqual(sts.request["ExternalId"], created["external_id"])
        self.assertEqual(sts.request["RoleArn"], created["role_arn"])
        self.assertEqual(session.kwargs["aws_session_token"], "C")

    def test_invalid_aws_role_or_region_is_rejected(self):
        with self.assertRaises(ValueError):
            cloud_ops.configure_aws(self.db, "arn:aws:iam::123:role/nope", "us-east-1", "admin")
        with self.assertRaises(ValueError):
            cloud_ops.configure_aws(self.db, "arn:aws:iam::123456789012:role/ReadOnly", "not-a-region", "admin")

    def test_azure_connection_validates_ids_and_does_not_accept_secrets(self):
        with self.assertRaises(ValueError):
            cloud_ops.configure_azure(self.db, "not-a-tenant", "not-a-subscription", "not-a-client", "admin")
        result = cloud_ops.configure_azure(
            self.db, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "admin")
        self.assertFalse(result["enabled"])
        status = cloud_ops.get_connection(self.db, "azure")
        self.assertEqual(status["subscription_id"], result["subscription_id"])
        self.assertNotIn("client_secret", status)

    def test_same_cloud_identity_cannot_be_shared_between_workspaces(self):
        auth_db = Path(self.temp.name) / "auth.sqlite3"
        cloud_ops.reserve_workspace_identity(auth_db, "tenant-a", "aws", "arn:aws:iam::123456789012:role/ReadOnly")
        with self.assertRaises(PermissionError):
            cloud_ops.reserve_workspace_identity(auth_db, "tenant-b", "aws", "arn:aws:iam::123456789012:role/ReadOnly")
        cloud_ops.reserve_workspace_identity(auth_db, "tenant-a", "aws", "arn:aws:iam::123456789012:role/ReadOnly2")

    def test_duplicate_workspace_binding_is_rejected_before_connection_is_saved(self):
        auth_db = Path(self.temp.name) / "auth.sqlite3"
        role = "arn:aws:iam::123456789012:role/CloudShieldReadOnly"
        cloud_ops.configure_aws(self.db, role, "us-east-1", "admin-a",
                                auth_db_path=auth_db, tenant_id="tenant-a")
        second_db = Path(self.temp.name) / "tenant-b.sqlite3"
        with self.assertRaises(PermissionError):
            cloud_ops.configure_aws(second_db, role, "us-east-1", "admin-b",
                                    auth_db_path=auth_db, tenant_id="tenant-b")
        self.assertIsNone(cloud_ops.get_connection(second_db, "aws"))

    def test_collection_enable_requires_successful_connection_test(self):
        cloud_ops.configure_aws(self.db, "arn:aws:iam::123456789012:role/CloudShieldReadOnly", "us-east-1", "admin")
        with self.assertRaises(PermissionError):
            cloud_ops.set_enabled(self.db, "aws", True)
        cloud_ops.mark_provider(self.db, "aws", status="connected")
        enabled = cloud_ops.set_enabled(self.db, "aws", True)
        self.assertTrue(enabled["enabled"])
        paused = cloud_ops.set_enabled(self.db, "aws", False)
        self.assertFalse(paused["enabled"])
        self.assertEqual(paused["status"], "connected")

    def test_collection_is_disabled_by_default_and_missing_provider_rejected(self):
        cloud_ops.configure_aws(self.db, "arn:aws:iam::123456789012:role/CloudShieldReadOnly", "us-east-1", "admin")
        with self.assertRaises(PermissionError):
            cloud_ops.aws_session(self.db)
        with self.assertRaises(ValueError):
            cloud_ops.set_enabled(self.db, "gcp", True)

    def test_alerts_are_high_severity_only_and_deduplicated(self):
        finding = {"event_id": "evt-1", "rule_id": "iam.suspicious", "severity": "HIGH",
                   "title": "Suspicious IAM action", "rationale": "Review the actor."}
        low = {"event_id": "evt-2", "rule_id": "low", "severity": "LOW"}
        self.assertEqual(cloud_ops.sync_alerts(self.db, [finding, low]), 1)
        self.assertEqual(cloud_ops.sync_alerts(self.db, [finding]), 0)
        alerts = cloud_ops.list_alerts(self.db)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        ack = cloud_ops.acknowledge_alert(self.db, alerts[0]["alert_id"], "responder-1")
        self.assertEqual(ack["acknowledged_by"], "responder-1")

    def test_response_requires_existing_finding_and_independent_approval(self):
        finding = {"event_id": "evt-1", "rule_id": "iam.suspicious", "severity": "HIGH"}
        finding_id = hashlib.sha256(json.dumps(["evt-1", "iam.suspicious"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with sqlite3_connect(self.db) as db:
            db.execute("CREATE TABLE findings (finding_id TEXT PRIMARY KEY,event_id TEXT,rule_id TEXT,payload_json TEXT,payload_sha256 TEXT)")
            db.execute("INSERT INTO findings VALUES(?,?,?,?,?)", (finding_id, "evt-1", "iam.suspicious", json.dumps(finding), "digest"))
        request = cloud_ops.request_response(self.db, finding_id, "review_and_revoke_suspicious_credentials",
                                             "Confirm key owner and preserve evidence.", "requester")
        with self.assertRaises(PermissionError):
            cloud_ops.decide_response(self.db, request["request_id"], "requester", True)
        approved = cloud_ops.decide_response(self.db, request["request_id"], "independent-admin", True, "Reviewed")
        self.assertEqual(approved["status"], "approved")
        with self.assertRaises(ValueError):
            cloud_ops.decide_response(self.db, request["request_id"], "another-admin", True)

    def test_inventory_upserts_by_provider_and_resource(self):
        first = cloud_ops.store_inventory(self.db, "aws", [{"resource_id":"i-123", "resource_type":"ec2-instance", "region":"us-east-1"}])
        second = cloud_ops.store_inventory(self.db, "aws", [{"resource_id":"i-123", "resource_type":"ec2-instance", "region":"us-west-2"}])
        self.assertEqual(first, 1)
        self.assertEqual(second, 1)
        inventory = cloud_ops.list_inventory(self.db, "aws")
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["region"], "us-west-2")

    def test_alert_email_goes_only_to_active_admins_and_responders(self):
        auth_db = Path(self.temp.name) / "auth.sqlite3"
        db = sqlite3.connect(auth_db)
        try:
            db.execute("CREATE TABLE users(user_id TEXT,tenant_id TEXT,email TEXT,role TEXT,active INTEGER)")
            db.executemany("INSERT INTO users VALUES(?,?,?,?,?)", [
                ("admin-1","tenant-a","admin@example.test","admin",1),
                ("resp-1","tenant-a","responder@example.test","responder",1),
                ("analyst-1","tenant-a","analyst@example.test","analyst",1),
                ("admin-2","tenant-b","other@example.test","admin",1),
            ])
            db.commit()
        finally:
            db.close()
        cloud_ops.sync_alerts(self.db, [{"event_id":"e1","rule_id":"r1","severity":"CRITICAL","title":"Critical finding"}])
        with patch.dict(os.environ, {}, clear=True):
            queued = cloud_ops.deliver_alert_notifications(self.db, auth_db, "tenant-a")
        self.assertEqual(queued["queued"], 2)
        db = sqlite3.connect(auth_db)
        try:
            db.execute("UPDATE users SET active=0 WHERE user_id='resp-1'")
            db.commit()
        finally:
            db.close()
        class FakeSMTP:
            def __init__(self,*args,**kwargs): self.messages=[]
            def ehlo(self): pass
            def starttls(self,**kwargs): pass
            def login(self,*args): pass
            def send_message(self,message): self.messages.append(message)
            def quit(self): pass
        fake = FakeSMTP()
        password_file = Path(self.temp.name) / "smtp-password"
        password_file.write_text("test-password", encoding="utf-8")
        env = {"CLOUDSHIELD_SMTP_HOST":"smtp.example.test", "CLOUDSHIELD_SMTP_USERNAME":"cloudshield",
               "CLOUDSHIELD_SMTP_PASSWORD_FILE":str(password_file), "CLOUDSHIELD_SMTP_FROM":"alerts@example.test"}
        with patch.dict(os.environ, env, clear=False):
            result = cloud_ops.deliver_alert_notifications(self.db, auth_db, "tenant-a", smtp_factory=lambda *a,**k: fake)
        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["cancelled"], 1)
        self.assertEqual({m["To"] for m in fake.messages}, {"admin@example.test"})
        self.assertTrue(all("raw event payload" in m.get_content() for m in fake.messages))

    def test_response_recommendations_match_finding_type(self):
        s3 = cloud_ops.recommendations({"rule_id":"s3.public_bucket_policy"})
        network = cloud_ops.recommendations({"rule_id":"ec2.public_admin_ingress"})
        self.assertEqual([item["action"] for item in s3], ["remove_unintended_public_access"])
        self.assertEqual([item["action"] for item in network], ["restrict_exposed_network_rule"])

    def test_response_execution_fails_closed(self):
        with self.assertRaises(RuntimeError):
            cloud_ops.execute_response("anything")


class sqlite3_connect:
    def __init__(self, path):
        import sqlite3
        self.db = sqlite3.connect(path)
    def __enter__(self):
        return self.db
    def __exit__(self, *args):
        self.db.commit()
        self.db.close()


if __name__ == "__main__":
    unittest.main()
