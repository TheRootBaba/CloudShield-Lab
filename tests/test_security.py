import os
import unittest
from unittest.mock import patch
from cloudshield.security import SlidingWindowLimiter, authenticate, role_allowed

class SecurityPrimitiveTests(unittest.TestCase):
    def test_tokens_require_strength_and_unique_values(self):
        with patch.dict(os.environ, {"CLOUDSHIELD_ADMIN_TOKEN": "short"}, clear=True):
            with self.assertRaises(RuntimeError): authenticate(None)
        token="a"*40
        with patch.dict(os.environ, {"CLOUDSHIELD_ADMIN_TOKEN": token, "CLOUDSHIELD_ANALYST_TOKEN": token}, clear=True):
            with self.assertRaises(RuntimeError): authenticate("Bearer " + token)

    def test_authentication_and_role_boundaries(self):
        admin="a"*40; responder="r"*40; analyst="v"*40
        env={"CLOUDSHIELD_ADMIN_TOKEN":admin,"CLOUDSHIELD_RESPONDER_TOKEN":responder,"CLOUDSHIELD_ANALYST_TOKEN":analyst}
        with patch.dict(os.environ,env,clear=True):
            self.assertIsNone(authenticate(None))
            self.assertIsNone(authenticate("Bearer wrong"))
            self.assertEqual("analyst",authenticate("Bearer "+analyst))
            self.assertTrue(role_allowed("analyst","GET","/api/incidents"))
            self.assertTrue(role_allowed("analyst","POST","/api/evidence/verify"))
            self.assertFalse(role_allowed("analyst","PATCH","/api/incidents/id/workflow"))
            self.assertFalse(role_allowed("responder","POST","/api/collector/aws"))
            self.assertTrue(role_allowed("admin","POST","/api/collector/aws"))

    def test_sliding_window_rate_limit(self):
        limiter=SlidingWindowLimiter(2,60)
        self.assertTrue(limiter.allow("127.0.0.1"))
        self.assertTrue(limiter.allow("127.0.0.1"))
        self.assertFalse(limiter.allow("127.0.0.1"))
        self.assertTrue(limiter.allow("127.0.0.2"))

if __name__ == "__main__": unittest.main()
