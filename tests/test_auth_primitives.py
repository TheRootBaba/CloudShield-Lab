import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cloudshield.auth import AuthStore, Session, _password_hash, _password_ok, cookie_header
from cloudshield import api


class AuthPrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = AuthStore(root / "auth.sqlite3", root / "tenants")
        self.admin = self.store.register("admin@example.test", "Admin", "a sufficiently long passphrase", "Primary")
        self.session, self.token = self.store.login("admin@example.test", "a sufficiently long passphrase")

    def tearDown(self):
        self.temp.cleanup()

    def test_password_verifier_rejects_malformed_and_wrong_hashes(self):
        encoded = _password_hash("a sufficiently long passphrase")
        self.assertTrue(_password_ok("a sufficiently long passphrase", encoded))
        self.assertFalse(_password_ok("incorrect password", encoded))
        self.assertFalse(_password_ok("x", "not-a-valid-hash"))
        self.assertFalse(_password_ok("x", "argon2$1$2$3$aa$bb"))

    def test_registration_validation_duplicate_and_missing_invitation(self):
        for email in ("", "missing-at-sign", "@example.test", "a@" + "x"*260, "first last@example.test", "a@b", "a@example.test."):
            with self.assertRaises(ValueError):
                self.store.register(email, "Person", "a sufficiently long passphrase")
        with self.assertRaises(ValueError):
            self.store.register("new@example.test", "", "a sufficiently long passphrase")
        with self.assertRaises(ValueError):
            self.store.register("new@example.test", ["not", "text"], "a sufficiently long passphrase")
        with self.assertRaises(ValueError):
            self.store.register("new@example.test", "Person", "short")
        with self.assertRaises(PermissionError):
            self.store.register("new@example.test", "Person", "a sufficiently long passphrase")
        with self.assertRaises(PermissionError):
            self.store.register("new@example.test", "Person", "a sufficiently long passphrase", invite="invalid")
        with self.assertRaises(ValueError):
            self.store.register("new@example.test", "Person", "a sufficiently long passphrase", invite=["invalid"])
        with self.assertRaises(ValueError):
            self.store.register("admin@example.test", "Admin", "a sufficiently long passphrase")

    def test_login_unknown_bad_password_and_lockout(self):
        with self.assertRaises(PermissionError):
            self.store.login("missing@example.test", "a sufficiently long passphrase")
        with self.assertRaises(PermissionError):
            self.store.login("admin@example.test", "x" * 10000)
        with self.assertRaises(PermissionError):
            self.store.login("x" * 10000, "a sufficiently long passphrase")
        for _ in range(8):
            with self.assertRaises(PermissionError):
                self.store.login("admin@example.test", "wrong passphrase")
        with self.assertRaises(PermissionError) as locked:
            self.store.login("admin@example.test", "a sufficiently long passphrase")
        self.assertIn("locked", str(locked.exception).lower())

    def test_invite_role_and_workspace_admin_boundaries(self):
        analyst = Session("u2", self.session.tenant_id, "a@example.test", "Analyst", "analyst", "csrf", self.session.expires_at)
        with self.assertRaises(PermissionError):
            self.store.create_invite(analyst, "analyst")
        with self.assertRaises(ValueError):
            self.store.create_invite(self.session, "admin")
        with self.assertRaises(ValueError):
            self.store.create_invite(self.session, [])
        with self.assertRaises(PermissionError):
            self.store.create_workspace_invite(analyst, "New workspace")
        with self.assertRaises(ValueError):
            self.store.create_workspace_invite(self.session, "")
        with self.assertRaises(ValueError):
            self.store.create_workspace_invite(self.session, ["not", "text"])
        with self.assertRaises(PermissionError):
            self.store.members(analyst)
        with self.assertRaises(PermissionError):
            self.store.disable_member(analyst, self.session.user_id)

    def test_member_disable_self_and_unknown_member_are_rejected(self):
        with self.assertRaises(ValueError):
            self.store.disable_member(self.session, self.session.user_id)
        with self.assertRaises(ValueError):
            self.store.disable_member(self.session, "not-a-member")

    def test_forwarded_ip_header_cannot_spoof_rate_limit_identity(self):
        handler = SimpleNamespace(headers={"X-Forwarded-For":"198.51.100.99"}, client_address=("127.0.0.1", 4567))
        self.assertEqual("127.0.0.1", api._client_ip(handler))

    def test_secure_cookie_attributes(self):
        value = cookie_header("cloudshield_session", "opaque", secure=True, max_age=43200, http_only=True)
        self.assertIn("HttpOnly", value)
        self.assertIn("Secure", value)
        self.assertIn("SameSite=Strict", value)
        self.assertIn("Max-Age=43200", value)


if __name__ == "__main__":
    unittest.main()
