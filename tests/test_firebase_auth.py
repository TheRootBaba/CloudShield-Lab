import tempfile
import unittest
from pathlib import Path

from cloudshield.auth import AuthStore


class FirebaseWorkspaceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = AuthStore(self.root / "auth.sqlite3", self.root / "tenants")

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_verified_firebase_identity_bootstraps_admin_and_session(self):
        user = self.store.register_firebase("firebase-uid-1", "admin@example.test", "Workspace Admin", "Blue Team")
        self.assertEqual("admin", user["role"])
        session, token = self.store.login_firebase("firebase-uid-1")
        self.assertEqual(user["user_id"], session.user_id)
        self.assertEqual(session.user_id, self.store.get_session(token).user_id)
        self.assertEqual(user, self.store.register_firebase("firebase-uid-1", "admin@example.test", "Ignored Name"))
        self.assertEqual(1, len(self.store.members(session)))

    def test_firebase_member_requires_single_use_invite_and_keeps_workspace_role(self):
        admin = self.store.register_firebase("admin-uid", "admin@example.test", "Admin", "SOC")
        admin_session, _ = self.store.login_firebase("admin-uid")
        invite = self.store.create_invite(admin_session, "responder")
        member = self.store.register_firebase("member-uid", "responder@example.test", "Responder", invite=invite["invite_code"])
        self.assertEqual("responder", member["role"])
        with self.assertRaises(PermissionError):
            self.store.register_firebase("other-uid", "other@example.test", "Other", invite=invite["invite_code"])

    def test_existing_local_email_is_never_automatically_linked(self):
        self.store.register("existing@example.test", "Existing", "a secure local password", "Existing Team")
        with self.assertRaisesRegex(PermissionError, "migrate/link"):
            self.store.register_firebase("new-firebase-uid", "existing@example.test", "Existing")

    def test_disabled_firebase_member_cannot_create_new_session(self):
        admin = self.store.register_firebase("admin-uid", "admin@example.test", "Admin", "SOC")
        admin_session, _ = self.store.login_firebase("admin-uid")
        invite = self.store.create_invite(admin_session, "analyst")
        member = self.store.register_firebase("member-uid", "analyst@example.test", "Analyst", invite=invite["invite_code"])
        self.store.disable_member(admin_session, member["user_id"])
        with self.assertRaisesRegex(PermissionError, "disabled"):
            self.store.login_firebase("member-uid")

    def test_firebase_invitation_input_must_be_bounded_text(self):
        self.store.register_firebase("admin-uid", "admin@example.test", "Admin", "SOC")
        with self.assertRaisesRegex(ValueError, "Invitation code must be text"):
            self.store.register_firebase("other-uid", "other@example.test", "Other", invite=["not", "text"])

    def test_firebase_uid_cannot_change_linked_verified_email(self):
        self.store.register_firebase("stable-uid", "first@example.test", "User", "Workspace")
        with self.assertRaisesRegex(PermissionError, "does not match"):
            self.store.register_firebase("stable-uid", "second@example.test", "User")


if __name__ == "__main__":
    unittest.main()
