import unittest
from cloudshield.attack_techniques import RULE_TECHNIQUES, catalog, techniques_for_rule
from cloudshield.assets import inventory, relationship_graph
from cloudshield.pipeline import analyze_payload

class AttackTechniqueTests(unittest.TestCase):
    def test_catalog_mapping_matches_all_rules_and_unknown_is_empty(self):
        ids={r["id"] for r in catalog()}
        self.assertEqual(ids,set(RULE_TECHNIQUES))
        self.assertEqual(techniques_for_rule("not-a-rule"),[])
    def test_mapping_returns_copy(self):
        item=techniques_for_rule("CS-IAM-001")
        item[0]["id"]="tampered"
        self.assertEqual(techniques_for_rule("CS-IAM-001")[0]["id"],"T1098")
    def test_finding_has_mapping(self):
        event={"eventID":"x","eventTime":"2026-01-01T00:00:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","userIdentity":{"arn":"arn:aws:iam::123456789012:user/a"},"requestParameters":{"userName":"a"}}
        result=analyze_payload(event)
        finding=result["findings"][0]
        self.assertEqual(finding["rule_id"],"CS-IAM-002")
        self.assertEqual(techniques_for_rule(finding["rule_id"])[0]["id"],"T1098.001")
    def test_only_conservative_rules_have_technique_links(self):
        # Exposure/configuration findings don't automatically imply the ATT&CK
        # technique was executed; keep their technique list empty.
        for rule_id in ("CS-NET-001","CS-NET-002","CS-KMS-001","CS-LAMBDA-001","CS-SH-001"):
            self.assertEqual([],techniques_for_rule(rule_id),rule_id)

class AdversarialDetectionTests(unittest.TestCase):
    def test_public_s3_policy_deny_statement_does_not_alert(self):
        event={"eventID":"deny-public","eventTime":"2026-01-01T00:00:00Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","requestParameters":{"bucketName":"b","policyDocument":{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}}}
        self.assertEqual([],analyze_payload(event)["findings"])
    def test_private_ipv6_ingress_does_not_alert(self):
        event={"eventID":"private-ipv6","eventTime":"2026-01-01T00:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","requestParameters":{"groupId":"sg-abc","ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipv6Ranges":[{"cidrIpv6":"2001:db8::/64"}]}]}}
        self.assertEqual([],analyze_payload(event)["findings"])

class AssetInventoryTests(unittest.TestCase):
    def setUp(self):
        payload=[
            {"eventID":"e1","eventTime":"2026-01-01T01:00:00Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","awsRegion":"us-east-1","recipientAccountId":"123456789012","userIdentity":{"arn":"arn:aws:iam::123456789012:user/a"},"requestParameters":{"bucketName":"example","policyDocument":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}}},
            {"eventID":"e2","eventTime":"2026-01-01T02:00:00Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","awsRegion":"us-east-1","recipientAccountId":"123456789012","userIdentity":{"arn":"arn:aws:iam::123456789012:user/a"},"requestParameters":{"groupId":"sg-123","ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}}
        ]
        self.result=analyze_payload(payload)
    def test_inventory_has_resources_and_findings(self):
        assets=inventory(self.result["events"],self.result["findings"])
        self.assertEqual(2,len(assets))
        bucket=next(a for a in assets if a["resource_id"]=="example")
        self.assertEqual("s3-bucket",bucket["resource_type"])
        self.assertEqual(1,bucket["finding_count"])
        self.assertEqual(["CRITICAL"],bucket["severities"])
        self.assertEqual("security-group",next(a for a in assets if a["resource_id"]=="sg-123")["resource_type"])
    def test_inventory_is_stable_and_graph_edges_contextual(self):
        assets=inventory(self.result["events"],self.result["findings"])
        graph=relationship_graph(self.result["events"],assets)
        self.assertTrue(any(e["relationship"]=="actor_touched_resource" for e in graph["edges"]))
        self.assertTrue(any(e["relationship"]=="resource_observed_in_account" for e in graph["edges"]))
        self.assertFalse(graph["complete"])
        self.assertIn("not causal",graph["semantics"])
    def test_no_unobserved_assets_in_empty_input(self):
        self.assertEqual([],inventory([],[]))
        self.assertEqual([],relationship_graph([],[])["edges"])

if __name__=="__main__":
    unittest.main()
