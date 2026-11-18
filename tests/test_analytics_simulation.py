import unittest
from cloudshield.events import load_events
from cloudshield.detector import analyze_event
from cloudshield.analytics import build_incidents, investigation
from cloudshield.simulator import SCENARIOS, simulate

class AnalyticsSimulationTests(unittest.TestCase):
    def test_all_simulations_trigger_one_finding(self):
        for name in SCENARIOS:
            with self.subTest(name=name):
                events=load_events(simulate(name,at="2026-11-18T10:00:00Z")["events"])
                findings=[f for e in events for f in analyze_event(e)]
                expected = 4 if name == "multi-stage-compromise" else 1
                self.assertEqual(len(findings), expected)
                self.assertEqual(len(build_incidents(events,findings)),1)
    def test_evidence_hash_and_investigation(self):
        events=load_events(simulate("public-s3-policy",at="2026-11-18T10:00:00Z")["events"])
        findings=[f for e in events for f in analyze_event(e)]
        report=investigation(events[0].event_id,events,findings)
        self.assertEqual(len(report["evidence"]["sha256"]),64)
        self.assertEqual(len(report["findings"]),1)
    def test_missing_event_raises_key_error(self):
        with self.assertRaises(KeyError): investigation("missing",[],[])
    def test_negative_correlation_window_rejected(self):
        with self.assertRaises(ValueError): build_incidents([],[],window_minutes=-1)

if __name__=="__main__": unittest.main()