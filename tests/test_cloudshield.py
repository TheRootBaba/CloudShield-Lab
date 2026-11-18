import unittest

from cloudshield import (
    apply_guarded_remediation,
    build_attack_graph,
    detect_risky_changes,
    find_attack_paths,
    normalize_cloudtrail,
    normalize_security_hub,
    parse_plan,
    propose_remediation,
    validate_fix,
)


class CloudShieldTests(unittest.TestCase):
    def test_public_security_group_is_detected(self):
        plan = {"resource_changes": [{
            "address": "aws_security_group.public",
            "type": "aws_security_group",
            "change": {
                "actions": ["create"],
                "after": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
            },
        }]}
        findings = detect_risky_changes(plan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_parse_plan_normalizes_actions(self):
        changes = parse_plan({"resource_changes": [{
            "address": "aws_s3_bucket.private",
            "type": "aws_s3_bucket",
            "change": {"actions": ["update"], "after": {"acl": "private"}},
        }]})
        self.assertEqual(changes[0].action, "update")

    def test_telemetry_normalization_is_safe(self):
        cloudtrail = normalize_cloudtrail({"Records": [{"eventName": "DeleteTrail", "eventSource": "cloudtrail.amazonaws.com"}]})
        security_hub = normalize_security_hub({"Findings": [{"Id": "1", "Severity": {"Label": "HIGH"}}]})
        self.assertEqual(cloudtrail[0]["event_name"], "DeleteTrail")
        self.assertEqual(security_hub[0]["severity"], "high")

    def test_attack_paths_handle_cycles(self):
        graph = build_attack_graph({"public": ["instance"], "instance": ["database"], "database": ["public"]})
        paths = find_attack_paths(graph, "public", "database")
        self.assertIn(["public", "instance", "database"], paths)

    def test_remediation_requires_approval(self):
        findings = detect_risky_changes({"resource_changes": [{
            "address": "aws_s3_bucket.public",
            "type": "aws_s3_bucket",
            "change": {"actions": ["update"], "after": {"acl": "public-read"}},
        }]})
        remediation = propose_remediation(findings)[0]
        result = apply_guarded_remediation(remediation)
        self.assertFalse(result.applied)
        self.assertTrue(result.dry_run)

    def test_validation_uses_explicit_recheck(self):
        finding = detect_risky_changes({"resource_changes": [{
            "address": "aws_s3_bucket.public",
            "type": "aws_s3_bucket",
            "change": {"actions": ["update"], "after": {"acl": "public-read"}},
        }]})[0]
        result = validate_fix(finding, lambda item: True)[0]
        self.assertTrue(result.passed)


if __name__ == "__main__":
    unittest.main()
