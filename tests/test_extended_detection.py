import unittest
from cloudshield.events import CloudEvent
from cloudshield.detector import analyze_event, RULE_CATALOG

class ExtendedDetectionTests(unittest.TestCase):
    def finding_ids(self, row):
        return {f.rule_id for f in analyze_event(CloudEvent.from_dict(row))}
    def test_catalog_is_documented_and_nonempty(self):
        self.assertGreaterEqual(len(RULE_CATALOG),10)
        self.assertTrue(all(item["id"] and item["events"] for item in RULE_CATALOG))
    def test_iam_access_key_creation(self):
        self.assertIn("CS-IAM-002",self.finding_ids({"eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","requestParameters":{"userName":"alice"}}))
    def test_cloudtrail_stop_logging(self):
        self.assertIn("CS-CT-001",self.finding_ids({"eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging"}))
    def test_kms_key_disable(self):
        self.assertIn("CS-KMS-001",self.finding_ids({"eventSource":"kms.amazonaws.com","eventName":"DisableKey"}))
    def test_open_non_admin_port(self):
        ids=self.finding_ids({"eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","requestParameters":{"ipPermissions":[{"ipProtocol":"tcp","fromPort":8080,"toPort":8080,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}})
        self.assertIn("CS-NET-002",ids)
        self.assertNotIn("CS-NET-001",ids)
    def test_public_lambda_permission(self):
        self.assertIn("CS-LAMBDA-001",self.finding_ids({"eventSource":"lambda.amazonaws.com","eventName":"AddPermission","requestParameters":{"functionName":"example","principal":"*"}}))
    def test_root_console_login(self):
        self.assertIn("CS-IAM-003",self.finding_ids({"eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","userIdentity":{"type":"Root"},"responseElements":{"ConsoleLogin":"Success"}}))
if __name__=="__main__": unittest.main()