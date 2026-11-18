import unittest
from cloudshield.graph import build_attack_path
from cloudshield.collector import collect_cloudtrail

class GraphCollectorTests(unittest.TestCase):
    def test_attack_path_is_explainable_and_not_causal(self):
        incident={"actor":"alice","timeline":[
            {"event_id":"e1","title":"Policy changed","rule_id":"CS-IAM-001","timestamp":"2026-01-01T00:00:00Z","resources":["role/a"]},
            {"event_id":"e2","title":"Key created","rule_id":"CS-IAM-002","timestamp":"2026-01-01T00:03:00Z","resources":["role/a"]},
        ]}
        graph=build_attack_path(incident)
        self.assertEqual(len(graph["event_nodes"]),2)
        self.assertEqual(len(graph["sequence_edges"]),1)
        self.assertIn("shared_resource",graph["sequence_edges"][0]["evidence"])
        self.assertTrue(any(node["kind"]=="actor" for node in graph["nodes"]))
        self.assertTrue(any(node["kind"]=="resource" for node in graph["nodes"]))
        self.assertFalse(graph["complete"])
        self.assertIn("do not establish causality",graph["semantics"])
    def test_collector_rejects_unbounded_lookback(self):
        with self.assertRaises(ValueError): collect_cloudtrail(lookback_minutes=1441)
if __name__=="__main__": unittest.main()