import unittest
from pathlib import Path
from cloudshield.evaluation import evaluate_file, evaluate_cases

ROOT = Path(__file__).resolve().parents[1]


class DetectionEvaluationTests(unittest.TestCase):
    def test_curated_corpus_has_no_regressions(self):
        result = evaluate_file(ROOT / "fixtures" / "detection_evaluation.json")
        self.assertEqual(40, result["case_count"])
        self.assertEqual(0, result["case_fail_count"])
        self.assertEqual(result["case_count"], result["case_pass_count"])
        self.assertEqual(1.0, result["micro_average"]["precision"])
        self.assertEqual(1.0, result["micro_average"]["recall"])
        self.assertIn("not representative production telemetry", result["corpus_scope"])

    def test_rejects_unknown_expected_rule(self):
        with self.assertRaises(ValueError):
            evaluate_cases([{
                "id": "bad", "label": "positive",
                "event": {"eventSource": "iam.amazonaws.com", "eventName": "PutRolePolicy"},
                "expected_rule_ids": ["NOT-A-RULE"],
            }])

    def test_rejects_malformed_expected_rule_ids(self):
        for value in ("RULE-ID", [1], {"rule": "value"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                evaluate_cases([{
                    "id": "bad-shape", "label": "negative",
                    "event": {"eventSource": "iam.amazonaws.com", "eventName": "GetRole"},
                    "expected_rule_ids": value,
                }])

    def test_rejects_duplicate_case_ids(self):
        case = {"id": "same", "label": "negative", "event": {"eventSource": "iam.amazonaws.com", "eventName": "GetRole"}}
        with self.assertRaises(ValueError):
            evaluate_cases([case, case])


if __name__ == "__main__":
    unittest.main()
