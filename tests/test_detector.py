import json
import unittest
from pathlib import Path

from cloudshield.cli import analyze_file
from cloudshield.detector import analyze_event
from cloudshield.events import CloudEvent


ROOT = Path(__file__).resolve().parents[1]


class DetectorTests(unittest.TestCase):
    def test_sample_fixture_detects_three_risks(self):
        result = analyze_file(ROOT / "fixtures" / "sample_cloudtrail.json")
        self.assertEqual(result["events_analyzed"], 3)
        self.assertEqual(result["events"][0]["account_id"], "111122223333")
        self.assertEqual(result["findings_count"], 3)
        self.assertEqual(
            {item["rule_id"] for item in result["findings"]},
            {"CS-IAM-001", "CS-S3-001", "CS-NET-001"},
        )

    def test_private_bucket_policy_is_not_flagged(self):
        event = CloudEvent.from_dict({
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "requestParameters": {
                "bucketName": "private",
                "policyDocument": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                        "Action": "s3:GetObject",
                    }]
                },
            },
        })
        self.assertEqual(analyze_event(event), [])

    def test_ssh_open_to_internet_is_flagged(self):
        event = CloudEvent.from_dict({
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {
                "ipPermissions": [{
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": [{"cidrIp": "0.0.0.0/0"}],
                }]
            },
        })
        findings = analyze_event(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_findings_include_explainable_confidence_tier(self):
        event = CloudEvent.from_dict({"eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","requestParameters":{"ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}})
        finding = analyze_event(event)[0].to_dict()
        self.assertEqual("HIGH", finding["confidence"])
        self.assertIn("explicit", finding["confidence_rationale"])

    def test_unrelated_event_produces_no_finding(self):
        event = CloudEvent.from_dict({
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "requestParameters": {},
        })
        self.assertEqual(analyze_event(event), [])


if __name__ == "__main__":
    unittest.main()
