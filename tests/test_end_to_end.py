import unittest
from cloudshield.events import load_events
from cloudshield.pipeline import analyze_payload
from cloudshield.simulator import SCENARIOS, simulate
from cloudshield.analytics import investigation, build_incidents
from cloudshield.detector import analyze_event

class EndToEndTests(unittest.TestCase):
    def test_all_scenarios_detect_and_correlate(self):
        for name in SCENARIOS:
            with self.subTest(name=name):
                payload=simulate(name,at="2026-01-01T00:00:00Z")
                result=analyze_payload(payload["events"])
                self.assertEqual(result["events_analyzed"],1)
                self.assertEqual(result["findings_count"],1)
                self.assertEqual(result["incidents_count"],1)
                self.assertEqual(result["incidents"][0]["timeline"][0]["event_id"],payload["events"][0]["eventID"])
    def test_investigation_contains_evidence_hash(self):
        rows=[simulate("public-s3-policy")["events"][0]]
        events=load_events(rows)
        findings=[f for e in events for f in analyze_event(e)]
        report=investigation(events[0].event_id,events,findings)
        self.assertEqual(len(report["evidence"]["sha256"]),64)
        self.assertEqual(len(report["findings"]),1)
    def test_securityhub_findings_are_normalized_and_detected(self):
        payload={"Findings":[{"Id":"sh-123","Title":"Public S3 bucket","AwsAccountId":"123456789012","Region":"us-east-1","UpdatedAt":"2026-01-01T00:00:00Z","Severity":{"Label":"HIGH"},"Resources":[{"Id":"arn:aws:s3:::example"}],"Types":["Software and Configuration Checks"]}]}
        result=analyze_payload(payload)
        self.assertEqual(result["events"][0]["source_format"],"securityhub")
        self.assertEqual(result["findings"][0]["rule_id"],"CS-SH-001")
        self.assertEqual(result["findings"][0]["severity"],"HIGH")
    def test_invalid_payload_rejected(self):
        with self.assertRaises(ValueError): load_events("not-json")
    def test_unknown_scenario_rejected(self):
        with self.assertRaises(ValueError): simulate("not-a-scenario")
    def test_incident_ids_deterministic(self):
        row=simulate("iam-policy-escalation",at="2026-01-01T00:00:00Z")["events"]
        self.assertEqual(analyze_payload(row)["incidents"][0]["incident_id"],analyze_payload(row)["incidents"][0]["incident_id"])
    def test_time_window_splits_distant_activity(self):
        first=simulate("iam-policy-escalation",at="2026-01-01T00:00:00Z")["events"][0]
        second=simulate("public-s3-policy",at="2026-01-01T02:00:00Z")["events"][0]
        second["eventID"]="sim-s3-later"
        events=load_events([first,second])
        findings=[f for e in events for f in analyze_event(e)]
        self.assertEqual(len(build_incidents(events,findings,window_minutes=30)),2)
        self.assertEqual(len(build_incidents(events,findings,window_minutes=180)),1)
if __name__=="__main__": unittest.main()
