import unittest
from datetime import datetime, timezone

from cloudshield.aws_inventory import collect_inventory


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def _call(self, name, **kwargs):
        self.calls.append((name, kwargs))
        response = self.responses[name]
        if isinstance(response, list):
            return response.pop(0)
        return response

    def describe_instances(self, **kwargs):
        return self._call("describe_instances", **kwargs)

    def describe_security_groups(self, **kwargs):
        return self._call("describe_security_groups", **kwargs)

    def list_buckets(self, **kwargs):
        return self._call("list_buckets", **kwargs)

    def list_roles(self, **kwargs):
        return self._call("list_roles", **kwargs)

    def list_users(self, **kwargs):
        return self._call("list_users", **kwargs)


class FakeSession:
    def __init__(self):
        self.clients = {
            "ec2": FakeClient({
                "describe_instances": {"Reservations": [{"Instances": [{
                    "InstanceId": "i-123", "InstanceType": "t3.micro",
                    "State": {"Name": "running"}, "VpcId": "vpc-1",
                    "SecurityGroups": [{"GroupId": "sg-1"}],
                    "Tags": [{"Key": "Name", "Value": "lab"}],
                }]}]},
                "describe_security_groups": {"SecurityGroups": [{
                    "GroupId": "sg-1", "GroupName": "default",
                    "IpPermissions": [], "IpPermissionsEgress": [],
                }]},
            }),
            "s3": FakeClient({"list_buckets": {"Buckets": [
                {"Name": "lab-bucket", "CreationDate": datetime(2026, 1, 1, tzinfo=timezone.utc)}
            ]}}),
            "iam": FakeClient({
                "list_roles": {"Roles": [{"Arn": "arn:aws:iam::123:role/lab", "RoleName": "lab"}], "IsTruncated": False},
                "list_users": {"Users": [{"Arn": "arn:aws:iam::123:user/alice", "UserName": "alice"}], "IsTruncated": False},
            }),
        }

    def client(self, name, region_name=None):
        return self.clients[name]


class AwsInventoryTests(unittest.TestCase):
    def test_bounded_read_only_inventory_shapes(self):
        session = FakeSession()
        result = collect_inventory(["us-east-1"], session=session)
        self.assertEqual("live-read-only", result["execution"])
        self.assertEqual(5, result["api_calls"])
        self.assertFalse(result["complete"])
        self.assertEqual(5, result["resource_count"])
        self.assertEqual({"ec2-instance", "security-group", "s3-bucket", "iam-role", "iam-user"},
                         {r["resource_type"] for r in result["resources"]})
        self.assertIn("ec2:DescribeInstances", result["permissions_required"]["ec2"])
        self.assertTrue(all("create" not in name.lower() and "delete" not in name.lower()
                            for client in session.clients.values() for name, _ in client.calls))

    def test_region_and_page_bounds(self):
        with self.assertRaises(ValueError):
            collect_inventory([], session=FakeSession())
        with self.assertRaises(ValueError):
            collect_inventory(["us-east-1", "us-east-1"], session=FakeSession())
        with self.assertRaises(ValueError):
            collect_inventory(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ca-central-1", "eu-central-1"], session=FakeSession())
        with self.assertRaises(ValueError):
            collect_inventory(["us-east-1"], max_pages=3, session=FakeSession())

    def test_iam_marker_pagination_and_truncation(self):
        session = FakeSession()
        iam = session.clients["iam"]
        iam.responses["list_roles"] = [
            {"Roles": [{"Arn": "arn:aws:iam::123:role/one"}], "IsTruncated": True, "Marker": "page-2"},
            {"Roles": [{"Arn": "arn:aws:iam::123:role/two"}], "IsTruncated": False},
        ]
        result = collect_inventory(["us-east-1"], max_pages=2, session=session)
        roles = [r for r in result["resources"] if r["resource_type"] == "iam-role"]
        self.assertEqual(2, len(roles))
        self.assertTrue(any(name == "list_roles" and kwargs.get("Marker") == "page-2"
                            for name, kwargs in iam.calls))

    def test_invalid_region_rejected_before_client_use(self):
        session = FakeSession()
        with self.assertRaises(ValueError):
            collect_inventory(["*"], session=session)
        self.assertTrue(all(not client.calls for client in session.clients.values()))


if __name__ == "__main__":
    unittest.main()
