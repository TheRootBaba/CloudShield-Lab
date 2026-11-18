import unittest

from cloudshield.graph import build_attack_path
from cloudshield.collector import collect_cloudtrail


class GraphCollectorTests(unittest.TestCase):
    def test_attack_path_is_explainable_and_not_causal(self):
        incident = {
            "actor": "alice",
            "account_id": "123456789012",
            "timeline": [
                {"event_id": "e1", "title": "Policy changed", "rule_id": "CS-IAM-001",
                 "timestamp": "2026-01-01T00:00:00Z", "resources": ["role/a"]},
                {"event_id": "e2", "title": "Key created", "rule_id": "CS-IAM-002",
                 "timestamp": "2026-01-01T00:03:00Z", "resources": ["role/a"]},
            ],
        }
        graph = build_attack_path(incident)
        self.assertEqual(len(graph["event_nodes"]), 2)
        self.assertEqual(len(graph["sequence_edges"]), 1)
        edge = graph["sequence_edges"][0]
        self.assertIn("shared_resource", edge["evidence"])
        self.assertFalse(edge["causal"])
        self.assertTrue(any(node["kind"] == "actor" for node in graph["nodes"]))
        self.assertTrue(any(node["kind"] == "resource" for node in graph["nodes"]))
        self.assertFalse(graph["complete"])
        self.assertIn("do not establish causality", graph["semantics"])

    def test_unrelated_events_are_not_linked_just_because_they_are_adjacent(self):
        graph = build_attack_path({
            "actor": "unknown",
            "timeline": [
                {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z", "resources": ["role/a"]},
                {"event_id": "e2", "timestamp": "2026-01-01T00:01:00Z", "resources": ["bucket/b"]},
            ],
        })
        self.assertEqual(graph["sequence_edges"], [])

    def test_events_more_than_24_hours_apart_are_not_linked(self):
        graph = build_attack_path({
            "actor": "alice",
            "timeline": [
                {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z"},
                {"event_id": "e2", "timestamp": "2026-01-03T00:00:00Z"},
            ],
        })
        self.assertEqual(graph["sequence_edges"], [])

    def test_duplicate_event_ids_are_made_unambiguous(self):
        graph = build_attack_path({
            "actor": "alice",
            "timeline": [{"event_id": "same"}, {"event_id": "same"}],
        })
        self.assertEqual([node["id"] for node in graph["event_nodes"]], ["same", "same#1"])

    def test_malformed_timeline_is_safe(self):
        self.assertEqual(build_attack_path({"timeline": None})["event_nodes"], [])
        self.assertEqual(build_attack_path({"timeline": ["bad", None]})["event_nodes"], [])

    def test_collector_rejects_unbounded_lookback(self):
        with self.assertRaises(ValueError):
            collect_cloudtrail(lookback_minutes=1441)


if __name__ == "__main__":
    unittest.main()
