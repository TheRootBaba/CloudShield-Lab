import http.cookiejar
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from cloudshield import api


class MultiUserApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_db = api.DB_PATH
        self.old_auth = api._AUTH_STORE
        api.DB_PATH = self.root / "legacy.sqlite3"
        api._AUTH_STORE = None
        api._AUTH_LIMITER = api.SlidingWindowLimiter(30)
        self.env = patch.dict(os.environ, {
            "CLOUDSHIELD_AUTH_MODE": "multi_user",
            "CLOUDSHIELD_AUTH_DB": str(self.root / "auth.sqlite3"),
            "CLOUDSHIELD_TENANT_DIR": str(self.root / "tenants"),
            "CLOUDSHIELD_COOKIE_SECURE": "0",
        }, clear=False)
        self.env.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.env.stop()
        api.DB_PATH = self.old_db
        api._AUTH_STORE = self.old_auth
        self.tmp.cleanup()

    def client(self):
        jar = http.cookiejar.CookieJar()
        opener = build_opener(HTTPCookieProcessor(jar))
        opener.cookiejar = jar
        return opener, jar

    def call(self, opener, path, method="GET", payload=None, csrf=True):
        headers = {}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        jar = opener.cookiejar
        if method in {"POST", "PATCH"} and csrf:
            token = next((c.value for c in jar if c.name == "cloudshield_csrf"), "")
            if token:
                headers["X-CSRF-Token"] = token
        req = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with opener.open(req, timeout=5) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else {}
        except HTTPError as exc:
            raw = exc.read()
            try:
                body = json.loads(raw) if raw else {}
            finally:
                status = exc.code
                exc.close()
            return status, body

    def test_bootstrap_signup_login_logout_and_csrf(self):
        opener, _ = self.client()
        self.assertEqual((200, {"enabled": True, "bootstrap_required": True, "bootstrap_token_required": False}), self.call(opener, "/api/auth/status"))
        status, created = self.call(opener, "/api/auth/register", "POST", {
            "email": "admin@example.test", "display_name": "Workspace Admin",
            "tenant_name": "Blue Team", "password": "correct horse battery staple"
        })
        self.assertEqual(200, status)
        self.assertEqual("admin", created["user"]["role"])
        self.assertEqual(200, self.call(opener, "/api/auth/me")[0])
        self.assertEqual(403, self.call(opener, "/api/simulate", "POST", {"scenario": "multi-stage-compromise"}, csrf=False)[0])
        self.assertEqual(200, self.call(opener, "/api/simulate", "POST", {"scenario": "multi-stage-compromise"})[0])
        self.assertEqual(200, self.call(opener, "/api/auth/logout", "POST", {})[0])
        self.assertEqual(401, self.call(opener, "/api/dashboard")[0])

    def test_separate_workspaces_have_separate_evidence_databases(self):
        first, _ = self.client()
        status, admin = self.call(first, "/api/auth/register", "POST", {
            "email": "owner@example.test", "display_name": "Owner",
            "tenant_name": "Northwind SOC", "password": "a sufficiently long passphrase"
        })
        self.assertEqual(200, status)
        self.assertEqual(200, self.call(first, "/api/simulate", "POST", {"scenario": "multi-stage-compromise"})[0])
        status, invitation = self.call(first, "/api/team/workspace-invites", "POST", {"workspace_name": "Contoso SOC"})
        self.assertEqual(201, status)
        second, _ = self.client()
        status, member = self.call(second, "/api/auth/register", "POST", {
            "email": "other@example.test", "display_name": "Other Admin",
            "password": "another sufficiently long passphrase", "invite_code": invitation["invite_code"]
        })
        self.assertEqual(200, status)
        self.assertEqual("admin", member["user"]["role"])
        self.assertEqual(0, self.call(second, "/api/dashboard")[1]["events_total"])
        self.assertEqual(200, self.call(second, "/api/simulate", "POST", {"scenario": "multi-stage-compromise"})[0])
        self.assertEqual(4, self.call(first, "/api/dashboard")[1]["events_total"])
        self.assertEqual(4, self.call(second, "/api/dashboard")[1]["events_total"])
        self.assertNotEqual(admin["user"]["tenant_id"], member["user"]["tenant_id"])
        first_incident = self.call(first, "/api/incidents")[1][0]["incident_id"]
        self.assertEqual(404, self.call(second, "/api/incidents/" + first_incident)[0])

    def test_invitation_is_single_use_and_roles_are_server_enforced(self):
        admin, _ = self.client()
        self.call(admin, "/api/auth/register", "POST", {
            "email": "admin@example.test", "display_name": "Admin",
            "tenant_name": "Test Workspace", "password": "a secure admin passphrase"
        })
        _, invite = self.call(admin, "/api/team/invites", "POST", {"role": "analyst"})
        analyst, _ = self.client()
        status, member = self.call(analyst, "/api/auth/register", "POST", {
            "email": "analyst@example.test", "display_name": "Read Only",
            "password": "a secure analyst passphrase", "invite_code": invite["invite_code"]
        })
        self.assertEqual(200, status)
        self.assertEqual("analyst", member["user"]["role"])
        self.assertEqual(200, self.call(analyst, "/api/dashboard")[0])
        self.assertEqual(403, self.call(analyst, "/api/simulate", "POST", {"scenario": "all"})[0])
        third, _ = self.client()
        self.assertEqual(403, self.call(third, "/api/auth/register", "POST", {
            "email": "reuse@example.test", "display_name": "Reuse",
            "password": "a secure reused invitation", "invite_code": invite["invite_code"]
        })[0])


    def test_login_session_revocation_and_member_disable(self):
        admin, _ = self.client()
        self.call(admin, "/api/auth/register", "POST", {
            "email": "admin@example.test", "display_name": "Admin",
            "tenant_name": "Revocation Lab", "password": "a secure admin passphrase"
        })
        _, invitation = self.call(admin, "/api/team/invites", "POST", {"role": "responder"})
        member, _ = self.client()
        status, registered = self.call(member, "/api/auth/register", "POST", {
            "email": "member@example.test", "display_name": "Responder",
            "password": "a secure responder passphrase", "invite_code": invitation["invite_code"]
        })
        self.assertEqual(200, status)
        self.assertEqual(200, self.call(member, "/api/dashboard")[0])
        status, login = self.call(self.client()[0], "/api/auth/login", "POST", {
            "email": "member@example.test", "password": "a secure responder passphrase"
        })
        self.assertEqual(200, status)
        self.assertEqual("responder", login["user"]["role"])
        self.assertEqual(200, self.call(admin, "/api/team/members")[0])
        status, _ = self.call(admin, "/api/team/members/" + registered["user"]["user_id"] + "/disable", "POST", {})
        self.assertEqual(200, status)
        self.assertEqual(401, self.call(member, "/api/dashboard")[0])
        members = self.call(admin, "/api/team/members")[1]["members"]
        self.assertFalse(next(m for m in members if m["user_id"] == registered["user"]["user_id"])["active"])

    def test_shared_mode_never_exposes_or_uses_host_cloud_credentials(self):
        admin, _ = self.client()
        self.call(admin, "/api/auth/register", "POST", {
            "email": "admin@example.test", "display_name": "Admin",
            "tenant_name": "Shared Cloud", "password": "a secure admin passphrase"
        })
        with patch.dict(os.environ, {
            "CLOUDSHIELD_ENABLE_AWS_COLLECTOR": "1",
            "CLOUDSHIELD_ENABLE_AZURE_COLLECTION": "1",
            "AZURE_CLIENT_ID": "fake-client", "AZURE_TENANT_ID": "fake-tenant",
            "AZURE_CLIENT_SECRET": "fake-secret", "AZURE_SUBSCRIPTION_ID": "fake-subscription"
        }):
            providers = self.call(admin, "/api/providers")[1]["providers"]
            self.assertFalse(any(p.get("enabled") for p in providers))
            self.assertFalse(providers[0]["credentials_detected"])
            self.assertFalse(providers[1]["environment_credentials_configured"])
            self.assertEqual(403, self.call(admin, "/api/collector/aws", "POST", {})[0])
            self.assertEqual(403, self.call(admin, "/api/collector/azure/inventory", "POST", {})[0])


    def test_workspace_provider_configuration_is_scoped_and_disabled_by_default(self):
        admin, _ = self.client()
        status, _ = self.call(admin, "/api/auth/register", "POST", {
            "email":"admin@example.test", "display_name":"Admin", "tenant_name":"Provider Lab",
            "password":"a secure admin passphrase"
        })
        self.assertEqual(status, 200)
        status, configured = self.call(admin, "/api/providers/aws", "POST", {
            "role_arn":"arn:aws:iam::123456789012:role/CloudShieldReadOnly", "region":"us-east-1"
        })
        self.assertEqual(status, 201)
        self.assertTrue(configured["external_id"])
        providers = self.call(admin, "/api/providers")[1]["providers"]
        aws = next(item for item in providers if item["id"] == "aws")
        self.assertTrue(aws["configured"])
        self.assertEqual(aws["role_arn"], "arn:aws:iam::123456789012:role/CloudShieldReadOnly")
        self.assertEqual(aws["region"], "us-east-1")
        self.assertFalse(aws["enabled"])
        self.assertFalse(aws["credentials_detected"])
        status, blocked = self.call(admin, "/api/providers/aws/enable", "POST", {"enabled":True})
        self.assertEqual(status, 403)
        self.assertIn("Test the workspace cloud identity", blocked["error"])

        status, invite = self.call(admin, "/api/team/invites", "POST", {"role":"responder"})
        self.assertEqual(status, 201)
        responder, _ = self.client()
        status, _ = self.call(responder, "/api/auth/register", "POST", {
            "email":"responder@example.test", "display_name":"Responder", "password":"a secure responder passphrase",
            "invite_code":invite["invite_code"]
        })
        self.assertEqual(status, 200)
        status, _ = self.call(responder, "/api/providers/azure", "POST", {
            "tenant_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "subscription_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "managed_identity_client_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        })
        self.assertEqual(status, 403)

    def test_readiness_is_public_for_external_monitoring(self):
        admin, _ = self.client()
        status, _ = self.call(admin, "/api/auth/register", "POST", {
            "email":"admin@example.test", "display_name":"Admin", "tenant_name":"Monitor Lab",
            "password":"a secure admin passphrase"
        })
        self.assertEqual(status, 200)
        from cloudshield.worker import _record_heartbeat
        _record_heartbeat(Path(os.environ["CLOUDSHIELD_AUTH_DB"]))
        anonymous, _ = self.client()
        status, ready = self.call(anonymous, "/api/health/ready")
        self.assertEqual(status, 200)
        self.assertTrue(ready["ok"])

    def test_readiness_reports_worker_heartbeat(self):
        admin, _ = self.client()
        status, _ = self.call(admin, "/api/auth/register", "POST", {
            "email":"admin@example.test", "display_name":"Admin", "tenant_name":"Readiness Lab",
            "password":"a secure admin passphrase"
        })
        self.assertEqual(status, 200)
        status, ready = self.call(admin, "/api/health/ready")
        self.assertEqual(status, 503)
        self.assertEqual(ready["database"], "ok")
        self.assertEqual(ready["worker"], "not_started")
        from cloudshield.worker import _record_heartbeat
        _record_heartbeat(Path(os.environ["CLOUDSHIELD_AUTH_DB"]))
        status, ready = self.call(admin, "/api/health/ready")
        self.assertEqual(status, 200)
        self.assertEqual(ready["worker"], "running")
        auth_db = sqlite3.connect(os.environ["CLOUDSHIELD_AUTH_DB"])
        try:
            auth_db.execute("UPDATE worker_heartbeat SET heartbeat_at='2000-01-01T00:00:00Z' WHERE worker_id='primary'")
            auth_db.commit()
        finally:
            auth_db.close()
        status, ready = self.call(admin, "/api/health/ready")
        self.assertEqual(status, 503)
        self.assertEqual(ready["worker"], "stale")

    def test_alert_acknowledgement_and_independent_response_approval(self):
        admin, _ = self.client()
        status, _ = self.call(admin, "/api/auth/register", "POST", {
            "email":"admin@example.test", "display_name":"Admin", "tenant_name":"Response Lab",
            "password":"a secure admin passphrase"
        })
        self.assertEqual(status, 200)
        status, _ = self.call(admin, "/api/simulate", "POST", {"scenario":"multi-stage-compromise"})
        self.assertEqual(status, 200)
        alerts = self.call(admin, "/api/alerts")[1]
        self.assertTrue(alerts)
        findings = self.call(admin, "/api/findings")[1]
        finding = next(item for item in findings if item["severity"] in {"HIGH","CRITICAL"})
        guidance = self.call(admin, f"/api/findings/{finding['finding_id']}/recommendations")[1]
        self.assertTrue(guidance["recommendations"])
        status, invite = self.call(admin, "/api/team/invites", "POST", {"role":"responder"})
        self.assertEqual(status, 201)
        responder, _ = self.client()
        status, _ = self.call(responder, "/api/auth/register", "POST", {
            "email":"responder@example.test", "display_name":"Responder", "password":"a secure responder passphrase",
            "invite_code":invite["invite_code"]
        })
        self.assertEqual(status, 200)
        status, request = self.call(responder, "/api/responses", "POST", {
            "finding_id":finding["finding_id"], "action":guidance["recommendations"][0]["action"],
            "rationale":"Independent review requested based on the synthetic finding and linked event evidence."
        })
        self.assertEqual(status, 201)
        self.assertEqual(request["status"], "pending")
        self.assertEqual(403, self.call(responder, f"/api/responses/{request['request_id']}/decision", "POST", {"approve":True})[0])
        status, approved = self.call(admin, f"/api/responses/{request['request_id']}/decision", "POST", {"approve":True,"note":"Reviewed by workspace admin."})
        self.assertEqual(status, 200)
        self.assertEqual(approved["status"], "approved")
        self.assertFalse(guidance["execution_enabled"])
        status, acknowledged = self.call(responder, f"/api/alerts/{alerts[0]['alert_id']}/acknowledge", "POST", {})
        self.assertEqual(status, 200)
        self.assertIsNotNone(acknowledged["acknowledged_at"])

    def test_expired_session_and_cross_origin_mutation_are_rejected(self):
        opener, jar = self.client()
        status, _ = self.call(opener, "/api/auth/register", "POST", {
            "email": "admin@example.test", "display_name": "Admin",
            "tenant_name": "Origin Lab", "password": "a secure admin passphrase"
        })
        self.assertEqual(200, status)
        import sqlite3
        db = sqlite3.connect(Path(os.environ["CLOUDSHIELD_AUTH_DB"]))
        try:
            db.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'")
            db.commit()
        finally:
            db.close()
        self.assertEqual(401, self.call(opener, "/api/dashboard")[0])

        fresh, fresh_jar = self.client()
        self.call(fresh, "/api/auth/login", "POST", {
            "email": "admin@example.test", "password": "a secure admin passphrase"
        })
        csrf = next(c.value for c in fresh_jar if c.name == "cloudshield_csrf")
        request = Request(self.base + "/api/simulate", data=json.dumps({"scenario":"all"}).encode(),
                          headers={"Content-Type":"application/json", "Origin":"https://attacker.invalid",
                                   "X-CSRF-Token":csrf}, method="POST")
        with self.assertRaises(HTTPError) as denied:
            fresh.open(request, timeout=5)
        self.assertEqual(403, denied.exception.code)
        denied.exception.close()

    def test_auth_mode_disabled_reports_status_without_creating_auth_store(self):
        with patch.dict(os.environ, {"CLOUDSHIELD_AUTH_MODE": ""}):
            api._AUTH_STORE = None
            opener, _ = self.client()
            status, result = self.call(opener, "/api/auth/status")
            self.assertEqual(200, status)
            self.assertFalse(result["enabled"])
            self.assertIsNone(api._AUTH_STORE)


    def test_initial_admin_setup_key_is_required_when_configured(self):
        with patch.dict(os.environ, {"CLOUDSHIELD_BOOTSTRAP_TOKEN": "K" * 48}):
            opener, _ = self.client()
            status, state = self.call(opener, "/api/auth/status")
            self.assertEqual(200, status)
            self.assertTrue(state["bootstrap_token_required"])
            payload = {"email":"owner@example.test","display_name":"Owner","tenant_name":"Protected workspace","password":"a sufficiently long passphrase"}
            self.assertEqual(403, self.call(opener, "/api/auth/register", "POST", payload)[0])
            payload["bootstrap_token"] = "wrong-key"
            self.assertEqual(403, self.call(opener, "/api/auth/register", "POST", payload)[0])
            payload["bootstrap_token"] = "ðŸ”‘" * 48
            self.assertEqual(403, self.call(opener, "/api/auth/register", "POST", payload)[0])
            payload["bootstrap_token"] = {"unexpected": "object"}
            self.assertEqual(403, self.call(opener, "/api/auth/register", "POST", payload)[0])
            payload["bootstrap_token"] = "K" * 48
            self.assertEqual(200, self.call(opener, "/api/auth/register", "POST", payload)[0])
            status, state = self.call(opener, "/api/auth/status")
            self.assertEqual(200, status)
            self.assertFalse(state["bootstrap_required"])
            self.assertFalse(state["bootstrap_token_required"])


    def test_firebase_endpoint_verifies_claims_and_issues_workspace_session(self):
        claims = {"uid":"firebase-admin-uid","email":"firebase-admin@example.test",
                  "email_verified":True,"name":"Firebase Admin"}
        with patch.dict(os.environ, {"CLOUDSHIELD_AUTH_PROVIDER":"firebase",
                                     "CLOUDSHIELD_BOOTSTRAP_TOKEN":"B"*48}):
            with patch.object(api, "_verify_firebase_id_token", return_value=claims):
                opener, _ = self.client()
                status, config = self.call(opener, "/api/auth/config")
                self.assertEqual(200, status)
                self.assertEqual("firebase", config["provider"])
                status, result = self.call(opener, "/api/auth/firebase", "POST", {
                    "id_token":"test-signed-token", "bootstrap_token":"B"*48,
                    "tenant_name":"Firebase SOC"
                })
                self.assertEqual(200, status)
                self.assertEqual("admin", result["user"]["role"])
                self.assertEqual(200, self.call(opener, "/api/auth/me")[0])

    def test_firebase_provider_disables_legacy_password_login_and_registration(self):
        with patch.dict(os.environ, {"CLOUDSHIELD_AUTH_PROVIDER":"firebase"}):
            with patch.object(api, "_verify_firebase_id_token") as verifier:
                opener, _ = self.client()
                status, _ = self.call(opener, "/api/auth/login", "POST", {"email":"x@example.test","password":"password"})
                self.assertEqual(403, status)
                status, _ = self.call(opener, "/api/auth/register", "POST", {
                    "email":"x@example.test","display_name":"X","password":"a sufficiently long password"
                })
                self.assertEqual(403, status)
                verifier.assert_not_called()

    def test_firebase_endpoint_rejects_unverified_email_before_workspace_creation(self):
        claims = {"uid":"unverified-uid","email":"pending@example.test","email_verified":False}
        with patch.dict(os.environ, {"CLOUDSHIELD_AUTH_PROVIDER":"firebase"}):
            with patch.object(api, "_verify_firebase_id_token", return_value=claims):
                opener, _ = self.client()
                status, result = self.call(opener, "/api/auth/firebase", "POST", {"id_token":"test-token"})
                self.assertEqual(403, status)
                self.assertIn("Verify your email", result["error"])
                self.assertTrue(api._auth_store().bootstrap_required())


if __name__ == "__main__":
    unittest.main()
