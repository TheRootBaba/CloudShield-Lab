import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class InfrastructureFixtureTests(unittest.TestCase):
    def test_secure_baseline_enforces_expected_controls(self):
        source = (ROOT / "terraform" / "secure" / "main.tf").read_text()
        for expected in ("block_public_acls       = true", "block_public_policy     = true", "restrict_public_buckets = true", 'sse_algorithm = "AES256"', 'status = "Enabled"', "is_multi_region_trail         = true", "enable_logging                = true"):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)

    def test_vulnerable_fixture_is_explicit_and_isolated(self):
        source = (ROOT / "terraform" / "vulnerable" / "main.tf").read_text()
        self.assertIn("INTENTIONALLY INSECURE", source)
        self.assertIn('cidr_blocks = ["0.0.0.0/0"]', source)
        self.assertIn("block_public_policy     = false", source)

    def test_both_roots_default_to_no_resource_creation(self):
        for root in ("secure", "vulnerable"):
            source = (ROOT / "terraform" / root / "main.tf").read_text()
            with self.subTest(root=root):
                self.assertIn('variable "enable_lab_resources"', source)
                self.assertIn("default     = false", source)
                self.assertIn("count", source)

    def test_secure_and_vulnerable_are_separate_roots(self):
        self.assertTrue((ROOT / "terraform" / "secure" / "main.tf").is_file())
        self.assertTrue((ROOT / "terraform" / "vulnerable" / "main.tf").is_file())

if __name__ == "__main__":
    unittest.main()

[executed on device: babam-desktop (5b84c11b-7f66-494f-9e6d-0dd5f16de169)]